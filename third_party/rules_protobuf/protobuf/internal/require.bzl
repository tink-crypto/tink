def _needs_install(name, dep, hkeys=["sha256", "sha1", "tag"], verbose=0):

    # Does it already exist?
    existing_rule = native.existing_rule(name)
    if not existing_rule:
        return True

    # If it has already been defined and our dependency lists a
    # hash, do these match? If a hash mismatch is encountered, has
    # the user specifically granted permission to continue?
    for hkey in hkeys:
        expected = dep.get(hkey)
        actual = existing_rule.get(hkey)
        if expected:
            if expected != actual:
                msg = """
An existing {0} rule '{1}' was already loaded with a {2} value of '{3}'.  Refusing to overwrite this with the requested value ('{4}').
Either remove the pre-existing rule from your WORKSPACE or exclude it from loading by rules_protobuf.
""".format(existing_rule["kind"], name, hkey, actual, expected)

                fail(msg)
            else:
                if verbose > 1: print("Skip reload %s: %s = %s" % (name, hkey, actual))
                return False

    # No kheys for this rule - in this case no reload; first one loaded wins.
    if verbose > 1: print("Skipping reload of existing target %s" % name)
    return False


def _install(deps, verbose):
    """Install a list if dependencies for matching native rules.
    Return:
      list of deps that have no matching native rule.
    """
    todo = []

    for d in deps:
        name = d.get("name")
        rule = d.pop("rule", None)
        if not rule:
            fail("Missing attribute 'rule': %s" % name)
        if hasattr(native, rule):
            rule = getattr(native, rule)
            if verbose: print("Loading %s)" % name)
            rule(**d)
        else:
            d["rule"] = rule
            todo.append(d)

    return todo


def require(keys,
            deps = {},
            overrides = {},
            excludes = [],
            verbose = 0):

    #
    # Make a list of non-excluded required deps with merged data.
    #
    required = []

    for key in keys:
        dep = deps.get(key)
        if not dep:
            fail("Unknown workspace dependency: %s" % key)
        d = dict(**dep) # copy the 'frozen' object.
        if not key in excludes:
            over = overrides.get(key)
            data = d + over if over else d
            if _needs_install(key, data, verbose=verbose):
                data["name"] = key
                required.append(data)

    return _install(required, verbose)
