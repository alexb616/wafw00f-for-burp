#!/usr/bin/env python3
"""
convert_plugins.py — Convierte los plugins de wafw00f a un modelo de datos
(signatures.json) que el motor Java de la extensión evalúa en runtime.

Cada plugin de wafw00f es 100% declarativo: un NAME y una función is_waf(self)
que combina llamadas matchHeader / matchCookie / matchContent / matchStatus /
matchReason, con OR entre los checks de alto nivel y AND dentro de las
funciones check_schema_*. Este script parsea el AST de cada plugin y emite un
árbol booleano equivalente:

  nodo = {"op":"match", "type":"header|cookie|content|status|reason",
          "name":<header>, "pattern":<regex>, "status":<int>, "reason":<str>,
          "attack":<bool>}
        | {"op":"and", "nodes":[...]}
        | {"op":"or",  "nodes":[...]}
        | {"op":"not", "nodes":[<nodo>]}

Uso:
  python3 convert_plugins.py <ruta_wafw00f_pkg> <dir_salida_resources>

  <ruta_wafw00f_pkg>  carpeta 'wafw00f/' que contiene plugins/ y wafprio.py
  <dir_salida>        donde escribir signatures.json y wafprio.json
"""
import ast
import json
import os
import sys

# Valores por defecto del flag `attack` para cada método (ver wafw00f/main.py).
ATTACK_DEFAULT = {
    "matchHeader": False,
    "matchCookie": False,
    "matchContent": True,
    "matchStatus": True,
    "matchReason": True,
}
MATCH_METHODS = set(ATTACK_DEFAULT.keys())

anomalies = []


def is_const_bool(node, value):
    return isinstance(node, ast.Constant) and isinstance(node.value, bool) and node.value is value


def lit(node):
    """Devuelve el literal Python de un nodo Constant/Tuple, o lanza error."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Tuple):
        return tuple(lit(e) for e in node.elts)
    raise ValueError("literal no soportado: %s" % ast.dump(node))


def build_match(call):
    """Convierte una llamada self.matchX(...) en un nodo 'match'."""
    method = call.func.attr
    args = call.args
    kwargs = {k.arg: k.value for k in call.keywords}

    # Resolver el flag attack (keyword o posicional) con su valor por defecto.
    attack = ATTACK_DEFAULT[method]
    if "attack" in kwargs:
        attack = bool(lit(kwargs["attack"]))
    elif method in ("matchHeader", "matchCookie", "matchContent", "matchStatus", "matchReason") and len(args) >= 2:
        # 2º posicional = attack
        attack = bool(lit(args[1]))

    if method == "matchHeader":
        header, pattern = lit(args[0])
        return {"op": "match", "type": "header", "name": header, "pattern": pattern, "attack": attack}
    if method == "matchCookie":
        pattern = lit(args[0])
        return {"op": "match", "type": "cookie", "name": "Set-Cookie", "pattern": pattern, "attack": attack}
    if method == "matchContent":
        pattern = lit(args[0])
        return {"op": "match", "type": "content", "pattern": pattern, "attack": attack}
    if method == "matchStatus":
        code = lit(args[0])
        return {"op": "match", "type": "status", "status": int(code), "attack": attack}
    if method == "matchReason":
        reason = lit(args[0])
        return {"op": "match", "type": "reason", "reason": reason, "attack": attack}
    raise ValueError("método match desconocido: %s" % method)


def convert_cond(expr, helpers, slug):
    """Convierte una expresión-condición (test de un if) en un nodo."""
    if isinstance(expr, ast.BoolOp):
        op = "and" if isinstance(expr.op, ast.And) else "or"
        return {"op": op, "nodes": [convert_cond(v, helpers, slug) for v in expr.values]}
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        return {"op": "not", "nodes": [convert_cond(expr.operand, helpers, slug)]}
    if isinstance(expr, ast.Call):
        func = expr.func
        # self.matchX(...)
        if isinstance(func, ast.Attribute) and func.attr in MATCH_METHODS:
            return build_match(expr)
        # check_schema_XX(self) u otra función auxiliar del módulo
        if isinstance(func, ast.Name) and func.id in helpers:
            return convert_function(helpers[func.id], helpers, slug)
        raise ValueError("llamada no soportada: %s" % ast.dump(expr))
    raise ValueError("condición no soportada: %s" % ast.dump(expr))


def convert_function(func, helpers, slug):
    """Convierte el cuerpo de una función (is_waf o check_schema_*) en un nodo."""
    or_clauses = []   # de  'if C: return True'
    guards = []       # de  'if not C: return False'  -> C requerido
                      #  y  'if C: return False'      -> not C requerido

    for stmt in func.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue  # docstring
        if isinstance(stmt, ast.Return):
            continue  # return True/False terminal
        if isinstance(stmt, ast.If):
            if not (len(stmt.body) == 1 and isinstance(stmt.body[0], ast.Return)):
                anomalies.append("%s: if con cuerpo inesperado" % slug)
                continue
            ret = stmt.body[0].value
            returns_true = is_const_bool(ret, True)
            returns_false = is_const_bool(ret, False)
            test = stmt.test
            if stmt.orelse:
                anomalies.append("%s: if con 'else' no soportado" % slug)
            if returns_true:
                or_clauses.append(convert_cond(test, helpers, slug))
            elif returns_false:
                # guard: para llegar a return True hay que NO cumplir este return False
                if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    guards.append(convert_cond(test.operand, helpers, slug))  # strip 'not'
                else:
                    guards.append({"op": "not", "nodes": [convert_cond(test, helpers, slug)]})
            else:
                anomalies.append("%s: if que no devuelve bool constante" % slug)
            continue
        anomalies.append("%s: sentencia no soportada %s" % (slug, type(stmt).__name__))

    parts = []
    if guards:
        parts.append(guards[0] if len(guards) == 1 else {"op": "and", "nodes": guards})
    if or_clauses:
        parts.append(or_clauses[0] if len(or_clauses) == 1 else {"op": "or", "nodes": or_clauses})
    if guards and or_clauses:
        # No ocurre en los datos actuales; se avisa por si un plugin futuro lo introduce.
        anomalies.append("%s: mezcla guards(AND) + clauses(OR) en una función" % slug)

    if not parts:
        anomalies.append("%s: función sin condiciones" % slug)
        return {"op": "or", "nodes": []}
    return parts[0] if len(parts) == 1 else {"op": "and", "nodes": parts}


def simplify(node):
    """Aplana and/or anidados del mismo tipo y colapsa nodos de un solo hijo."""
    op = node.get("op")
    if op in ("and", "or"):
        flat = []
        for child in node["nodes"]:
            child = simplify(child)
            if child.get("op") == op:
                flat.extend(child["nodes"])
            else:
                flat.append(child)
        if len(flat) == 1:
            return flat[0]
        return {"op": op, "nodes": flat}
    if op == "not":
        return {"op": "not", "nodes": [simplify(node["nodes"][0])]}
    return node


def convert_plugin(path, slug):
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)

    name = None
    helpers = {}
    is_waf = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "NAME":
                    name = lit(node.value)
        elif isinstance(node, ast.FunctionDef):
            if node.name == "is_waf":
                is_waf = node
            else:
                helpers[node.name] = node

    if name is None or is_waf is None:
        anomalies.append("%s: falta NAME o is_waf" % slug)
        return None

    match = simplify(convert_function(is_waf, helpers, slug))
    return {"name": name, "slug": slug, "match": match}


def extract_prio(wafprio_path):
    with open(wafprio_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "wafdetectionsprio":
                    return list(ast.literal_eval(node.value))
    return []


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    pkg_dir = sys.argv[1]
    out_dir = sys.argv[2]
    plugin_dir = os.path.join(pkg_dir, "plugins")

    signatures = []
    count_conditions = 0

    def count_nodes(n):
        if n.get("op") == "match":
            return 1
        return sum(count_nodes(c) for c in n.get("nodes", []))

    for fn in sorted(os.listdir(plugin_dir)):
        if not fn.endswith(".py") or fn == "__init__.py":
            continue
        slug = fn[:-3]
        sig = convert_plugin(os.path.join(plugin_dir, fn), slug)
        if sig is not None:
            signatures.append(sig)
            count_conditions += count_nodes(sig["match"])

    prio = extract_prio(os.path.join(pkg_dir, "wafprio.py"))

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "signatures.json"), "w", encoding="utf-8") as f:
        json.dump({"source": "wafw00f", "signatures": signatures}, f, ensure_ascii=False, indent=1)
    with open(os.path.join(out_dir, "wafprio.json"), "w", encoding="utf-8") as f:
        json.dump({"priority": prio}, f, ensure_ascii=False, indent=1)

    print("Plugins convertidos : %d" % len(signatures))
    print("Condiciones (match) : %d" % count_conditions)
    print("Prioridad (nombres) : %d" % len(prio))
    if anomalies:
        print("\nANOMALÍAS (%d):" % len(anomalies))
        for a in anomalies:
            print("  - %s" % a)
    else:
        print("\nSin anomalías: todos los plugins se convirtieron limpiamente.")


if __name__ == "__main__":
    main()
