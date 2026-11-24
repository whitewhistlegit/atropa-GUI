from atropa.backend import m4lite

SPT = """
define(`search_dir_perms',`{ getattr search open }')
define(`read_file_perms',`{ getattr open read lock ioctl }')
define(`read_files_pattern',`
	allow $1 $2:dir search_dir_perms;
	allow $1 $3:file read_file_perms;
')
"""

IF = """
## <summary>Read things.</summary>
interface(`thing_read',`
	gen_require(`
		type thing_t;
	')
	read_files_pattern($1, thing_t, thing_t)
	optional_policy(`
		allow $1 thing_t:lnk_file read;
	')
	ifdef(`distro_nope',`
		allow $1 thing_t:file write;
	')
	tunable_policy(`thing_writes',`
		allow $1 thing_t:file append;
	')
')
"""


def macros():
    m = {}
    for text in (SPT, IF):
        for _, name, body, _ in m4lite.iter_definitions(m4lite.strip_comments(text)):
            m[name] = body
    return m


def rules(expander):
    text = expander.call("thing_read", ["dom_t"])
    out = {}
    for _, s, t, c, p in m4lite.extract_rules(text):
        out[(s, t, c)] = out.get((s, t, c), frozenset()) | p
    return out


def test_parse_args_strips_one_quote_level():
    args, end = m4lite.parse_args("(`a, b', c(d, e), `x `y' z')rest", 0)
    assert args == ["a, b", "c(d, e)", "x `y' z"]
    assert "(`a, b', c(d, e), `x `y' z')rest"[end:] == "rest"


def test_interface_expands_to_rules():
    got = rules(m4lite.Expander(macros()))
    assert got[("dom_t", "thing_t", "dir")] == {"getattr", "search", "open"}
    assert got[("dom_t", "thing_t", "file")] == {"getattr", "open", "read", "lock", "ioctl"}
    assert got[("dom_t", "thing_t", "lnk_file")] == {"read"}  # optional_policy taken


def test_ifdef_follows_defines():
    assert "write" not in rules(m4lite.Expander(macros()))[("dom_t", "thing_t", "file")]
    assert "write" in rules(m4lite.Expander(macros(), defined={"distro_nope"}))[("dom_t", "thing_t", "file")]


def test_tunable_grants_are_left_out_unless_asked_for():
    # A tunable that's off on this machine would grant nothing, and no build step says so.
    assert "append" not in rules(m4lite.Expander(macros()))[("dom_t", "thing_t", "file")]
    assert "append" in rules(m4lite.Expander(macros(), tunables=True))[("dom_t", "thing_t", "file")]


def test_nested_sets_flatten():
    got = list(m4lite.extract_rules("allow a_t { b_t c_t }:{ file dir } { { read open } getattr };"))
    assert len(got) == 4
    assert all(r[4] == {"read", "open", "getattr"} for r in got)
