{
  description = "ansible python env";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2505.0";
  };

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      python3 = pkgs.python311;
    in
    {
      devShells.x86_64-linux.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          openssl_3
          (python3.withPackages (
            p: with p; [
              paramiko
              ansible-core
              black
            ]
          ))
        ];
      };
    };
}
