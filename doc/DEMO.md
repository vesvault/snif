# Generating the SNIF demo GIF

The README features a short GIF of a connector getting a live, public,
browser-trusted HTTPS hostname. It is generated deterministically with
[vhs](https://github.com/charmbracelet/vhs) from [`demo.tape`](demo.tape), so it
can be regenerated whenever the flow changes.

## Prerequisites

- `vhs` installed (`brew install vhs`, or see the vhs repo).
- A built `snif-conn` on `PATH`, configured against a relay (defaults to the
  public relay at snif.host).
- A **pre-authorized** connector, so the recording flows without the one-time
  browser authorization step. Replace `host1.snif.xyz` in `demo.tape` with this
  connector's real assigned hostname.

## Render

```sh
vhs doc/demo.tape        # writes doc/demo.gif
```

Then feature it in the README by uncommenting the image line under the intro:

```markdown
![SNIF in 30 seconds: connector to a live public HTTPS URL](doc/demo.gif)
```

## Notes

- Keep the GIF short (under ~30s) and the terminal wide enough to avoid line
  wrapping; tune `Set Width`/`Set FontSize` in `demo.tape` if needed.
- Alternative: `asciinema rec` produces an embeddable terminal cast, but needs
  hosting or a converter to turn it into a GIF for the README.
