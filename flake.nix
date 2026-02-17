{
  description = "OpenClaw NixOS modules (container + microVM)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    microvm = {
      url = "github:astro/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix-openclaw = {
      url = "github:openclaw/nix-openclaw";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    opencode = {
      url = "github:anomalyco/opencode";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, microvm, nix-openclaw, opencode }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    nixosModules = {
      openclaw = ./modules/openclaw;
      openclaw-vm = ./modules/openclaw-vm;
      openclaw-vm-guest = ./modules/openclaw-vm/guest.nix;
      default = { imports = [
        self.nixosModules.openclaw
        self.nixosModules.openclaw-vm
      ]; };
    };

    nixosConfigurations.test-vm = nixpkgs.lib.nixosSystem {
      inherit system;
      specialArgs = {
        pkgs-unstable = pkgs;
        inherit nix-openclaw opencode;
      };
      modules = [
        microvm.nixosModules.host
        self.nixosModules.openclaw-vm
        {
          CUSTOM.virtualisation.openclaw-vm = {
            enable = true;
            dangerousDevMode.enable = true;
            useVirtiofs = true;
            secrets.enable = false;
            tailscale.enable = false;
            caddy.enable = false;
            memory = 4096;
            vcpu = 2;
          };

          # Suppress unknown-option errors for sops.* paths defined in
          # mkIf blocks. Without sops-nix, the module system would error
          # on those option paths even though they're conditionally disabled.
          _module.check = false;

          # Minimal host config required for NixOS evaluation
          fileSystems."/" = {
            device = "/dev/vda";
            fsType = "ext4";
          };
          boot.loader.grub.device = "/dev/vda";
          networking.useDHCP = false;
          system.stateVersion = "25.11";
        }
      ];
    };

    packages.${system}.test-vm =
      self.nixosConfigurations.test-vm.config.microvm.vms.openclaw-vm.config.config.microvm.declaredRunner;

    checks.${system}.eval-test-vm = let
      toplevel = self.nixosConfigurations.test-vm.config.system.build.toplevel;
    in pkgs.runCommand "eval-test-vm" {} ''
      echo "Module evaluation succeeded: ${toplevel.name}" > $out
    '';
  };
}
