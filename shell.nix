{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShellNoCC {
  buildInputs = [
    pkgs.maven
    pkgs.jdk
  ];
}
