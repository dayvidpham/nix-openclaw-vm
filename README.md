# nix-openclaw-vm

OpenClaw NixOS modules for container-based and microVM-based deployments.

## Modules

- `openclaw` — Container-based OpenClaw deployment (9 NixOS modules + bridge script)
- `openclaw-vm` — MicroVM-based deployment (host module)
- `openclaw-vm-guest` — MicroVM guest configuration

## Usage

Add as a flake input:

```nix
{
  inputs.openclaw-modules.url = "github:dayvidpham/nix-openclaw-vm";
  inputs.openclaw-modules.inputs.nixpkgs.follows = "nixpkgs";
}
```

Then include in your NixOS configuration:

```nix
{ openclaw-modules, ... }: {
  imports = [ openclaw-modules.nixosModules.default ];
}
```

**Important:** The openclaw container modules require standalone `keycloak` and `openbao` modules in your module tree if using zero-trust mode.
