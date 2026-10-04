# Frame conditions

An outcome check asks *"did the agent do what was asked?"* A frame condition also
asks *"did it leave everything else alone?"* The name comes from the frame problem in
AI planning: specifying what an action does **not** change.

## Declaring a frame

The operator attaches an observer and a frame builder to a tool. The builder sees the
validated arguments, so the frame can be specific to one call:

```python
from secure_agent_runtime import FileTreeObserver, FrameSpec, Required

def frame_for(args):
    return FrameSpec(
        required=(Required("pyproject.toml", "modified",
                           before_contains=f'version = "{args.from_version}"',
                           after_contains=f'version = "{args.to_version}"'),),
        allowed=("uv.lock",),
        forbidden=("tests/**", ".github/**"),
    )

@registry.tool(input=BumpIn, output=BumpOut, effect=Effect.WRITE,
               observer=FileTreeObserver(workspace), frame=frame_for)
def bump_version(args): ...
```

The declared frame is **part of the action digest**. An approver approves the
arguments *and* the declared effects, and changing the frame builder after approval
blocks dispatch.

## Evaluation (`effects.check_frame`)

1. Diff the snapshots taken before dispatch and after the result. Each change is
   `added`, `modified` or `deleted`.
2. **Forbidden** is checked first, for every change. A change matching a forbidden glob
   is forbidden even if it also matches a requirement, so a broad requirement can't
   launder it.
3. **Required**: each requirement needs exactly `count` matching changes of the right
   kind, with `before_contains` / `after_contains` holding. One change satisfies at most
   one requirement (the first that matches it).
4. Remaining changes are **allowed** if they match an allowed glob, otherwise
   **undeclared**.
5. Verdict:
   * `violated` if anything is forbidden or undeclared, or a requirement is unmet;
   * `unverifiable` if a content check couldn't be made, for example because the
     pre-dispatch content was lost in a crash;
   * otherwise `verified`.

Globs are anchored. `*` and `?` stay inside one path segment; `**` crosses segments
and matches every character `*` can, including newlines. Everything else is literal.

## Observers

* `FileTreeObserver(root, ignore=...)` records regular files (content and permission
  bits), directories (so an empty new directory shows), and symlinks by target text,
  never followed. It does not see ownership, timestamps or extended attributes. A name
  that isn't valid UTF-8 makes the snapshot fail. Before dispatch that blocks the call;
  after dispatch it makes the verdict `unverifiable`. It is never reported as
  verified.
* `MappingObserver(source)` takes any `{str id: JSON value}`: a ledger, a table, a
  bucket listing. Non-string ids are refused, so `1` and `"1"` can't collide.
* Write your own by implementing `snapshot() -> {id: Entry(digest, content)}`.

## Demo

`secure-agent-runtime demo frame`: two agents bump 2.1.0 → 2.1.1. Both pass the
conventional check ("pyproject says 2.1.1"). The sloppy one also deleted
`tests/test_pkg.py` and edited `README.md`:

```
SLOPPY AGENT
  conventional outcome check:  PASS
  REQUIRED EFFECTS:            PASS
  UNDECLARED CHANGES:          1 ['README.md']
  FORBIDDEN EFFECTS:           1 ['tests/test_pkg.py']
  OUTCOME:                     VIOLATED
```

## Limits

* The observer sees only what it snapshots, and only at two instants. A change made
  and reverted in between, or outside the observed root, is invisible.
* Snapshots of large trees cost time proportional to their size (see the benchmark).
* A violated frame is reported, not undone. SAR runs the tool before it can observe
  the result. Pair it with a sandbox or a scratch copy if you need to discard bad
  changes.
* Concurrent writers to the observed state, including other agents, show up as
  undeclared changes.
