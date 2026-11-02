from mcp_authscan.surface import item_index, surface_digest

TOOLS = [{"name": "a", "description": "one"}, {"name": "b", "description": "two"}]


def test_order_independent():
    assert surface_digest({"tools": list(reversed(TOOLS))}) == surface_digest({"tools": TOOLS})


def test_prompt_change_moves_digest():
    before = {"prompts": [{"name": "p", "description": "x"}]}
    after = {"prompts": [{"name": "p", "description": "y"}]}
    assert surface_digest(before) != surface_digest(after)


def test_trailing_space_moves_digest():
    before = {"resources": [{"uri": "u", "description": "x"}]}
    after = {"resources": [{"uri": "u", "description": "x "}]}
    assert surface_digest(before) != surface_digest(after)


def test_instructions_move_digest():
    assert surface_digest({"instructions": "a"}) != surface_digest({"instructions": ""})


def test_item_index_keys():
    index = item_index({"tools": [{"name": "a"}], "prompts": [{"name": "p"}], "resources": [{"uri": "u"}]})
    assert set(index) == {"tool:a", "prompt:p", "resource:u"}

from mcp_authscan.surface import diff_surfaces


def test_identical_surface_has_no_changes():
    surface = {"tools": TOOLS, "instructions": "same"}
    assert diff_surfaces(surface, surface) == []


def test_added_and_removed():
    before = {"tools": [{"name": "a"}]}
    after = {"tools": [{"name": "b"}]}
    changes = sorted((row["key"], row["change"]) for row in diff_surfaces(before, after))
    assert changes == [("tool:a", "removed"), ("tool:b", "added")]


def test_changed_description_names_the_field():
    before = {"tools": [{"name": "a", "description": "one"}]}
    after = {"tools": [{"name": "a", "description": "two"}]}
    change = diff_surfaces(before, after)[0]
    assert change["change"] == "changed"
    assert change["fields"] == ["description"]


def test_reflow_is_labelled_whitespace():
    before = {"prompts": [{"name": "p", "description": "one two"}]}
    after = {"prompts": [{"name": "p", "description": "one   two"}]}
    assert diff_surfaces(before, after)[0]["change"] == "whitespace"


def test_instructions_change_comes_first():
    before = {"instructions": "a", "tools": [{"name": "a"}]}
    after = {"instructions": "b", "tools": [{"name": "a", "description": "x"}]}
    changes = diff_surfaces(before, after)
    assert changes[0]["key"] == "instructions:"
    assert changes[1]["key"] == "tool:a"
