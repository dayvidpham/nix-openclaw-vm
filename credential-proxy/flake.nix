{
  description = "Credential proxy for openclaw-vm (VSOCK MITM forward proxy)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.${system} = {
      credential-proxy = pkgs.buildGoModule {
        pname = "credential-proxy";
        version = "0.1.0";
        src = ./.;
        vendorHash = null;

        postInstall = ''
          mkdir -p $out/share/policies
          cp authz/policies/*.rego $out/share/policies/
        '';
      };
      default = self.packages.${system}.credential-proxy;
    };

    devShells.${system}.default = pkgs.mkShell {
      name = "credential-proxy-dev";
      inputsFrom = [ self.packages.${system}.credential-proxy ];
      packages = with pkgs; [
        gopls
        gotools       # goimports, etc.
        go-tools      # staticcheck
        delve         # debugger
        temporal-cli  # Temporal dev server
      ];
    };
  };
}
