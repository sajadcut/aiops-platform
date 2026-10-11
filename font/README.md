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

**License notice:** This public repository deliberately does not bundle the
IRANSansX binaries. IRANSansX may have commercial redistribution restrictions.
A license for local development or deploying to a website does **not**
necessarily authorize uploading font binaries to a public source repository.

If you are the license owner and your license explicitly permits public
redistribution in this repository, place all nine files here and run from the
repository root:

```powershell
.\scripts\publish-iransansx-fonts.ps1 -ConfirmPublicRedistribution -Push
```

The command refuses to publish without the explicit confirmation switch,
verifies the expected files and destination remote, and does not force-push.
Without redistribution rights, keep font binaries uncommitted and provision
them from a licensed private asset source at deploy time. The interface falls
back to a system Persian font when binaries are unavailable.

This README is not a license for IRANSansX and does not grant redistribution
rights.
