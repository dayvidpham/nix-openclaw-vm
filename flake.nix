{
  description = "OpenClaw NixOS modules (container + microVM)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }: {
    nixosModules = {
      openclaw = ./modules/openclaw;
      openclaw-vm = ./modules/openclaw-vm;
      openclaw-vm-guest = ./modules/openclaw-vm/guest.nix;
      default = { imports = [
        self.nixosModules.openclaw
        self.nixosModules.openclaw-vm
      ]; };
    };
  };
}
