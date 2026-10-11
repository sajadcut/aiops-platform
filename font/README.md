# IRANSansX font asset location

AIOps uses `/dashboard/fonts.css` to declare the **IRANSansX** font family
and serves allowlisted TrueType files from this directory via
`/assets/fonts/<filename>`.

The nine expected files are:

- `IRANSansXThin.ttf` (100)
- `IRANSansXUltraLight.ttf` (200)
- `IRANSansXLight.ttf` (300)
- `IRANSansXRegular.ttf` (400)
- `IRANSansXMedium.ttf` (500)
- `IRANSansXDemiBold.ttf` (600)
- `IRANSansXBold.ttf` (700)
- `IRANSansXExtraBold.ttf` (800)
- `IRANSansXBlack.ttf` (900)

**License notice:** The IRANSansX binaries were added to this public repository
by the project's font owner. Confirm that the actual font license authorizes
this form of redistribution; an ordinary end-user or web-embedding license may
not permit publishing font files as GitHub source assets. No third-party
redistribution rights are implied by this README.

If you are the license owner and your license explicitly permits public
redistribution in this repository, place all nine files here and run from the
repository root:

```powershell
.\scripts\publish-iransansx-fonts.ps1 -ConfirmPublicRedistribution -Push
```

The command refuses to publish without the explicit confirmation switch,
verifies the expected files and destination remote, and does not force-push.
If the actual license prohibits public redistribution, remove the binaries
from the public repository and provision them privately at deploy time.
The interface falls back to a system Persian font when binaries are unavailable.

This README is not a license for IRANSansX and does not grant redistribution
rights.

## Troubleshooting missing font in the browser

The browser must use the **same API instance** that serves the font routes.
After pulling `main` and restarting the API, run from the repository root:

```powershell
.\scripts\check-ui-fonts.ps1
```

For a nondefault API port, pass `-BaseUrl 'http://127.0.0.1:<port>'`.
The script reads the running dashboard, current `fonts.css?v=2` and all
nine `/assets/fonts/IRANSansX*.ttf?v=2` resources. It makes **no changes**.
When all checks pass, hard-reload the same browser URL and inspect the
DevTools **Network > Font** requests and the **Computed font-family** field.

If Git shows a clean working tree but a weight is missing from the local
directory, first check `git ls-files -v -- font/IRANSansXDemiBold.ttf`
and `git sparse-checkout list`; do not delete or reset unrelated changes.

A font change does **not** translate English text into Persian; that is
a separate UI localization task.
