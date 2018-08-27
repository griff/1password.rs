let
  unstable_overlay = self: super: {
    unstable = import (builtins.fetchTarball https://github.com/NixOS/nixpkgs-channels/archive/nixpkgs-unstable.tar.gz) {};
    _1password = self.unstable._1password;
  };
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  rust_replace = self: super: {
    rust = let
        rust_1_28 = (super.rustChannelOf { channel = "1.28.0"; }).rust;
        rust = rust_1_28; #super.rustChannels.stable.rust;
      in { rustc = rust; cargo = rust; };
    inherit (self.rust) rustc cargo;
  };
  orig = import <nixpkgs> {};
  nixpkgs = import <nixpkgs> { overlays = [ moz_overlay rust_replace unstable_overlay ]; };
in
  with nixpkgs;
  stdenv.mkDerivation {
    name = "moz_overlay_shell";
    buildInputs = [
      rustc cargo carnix _1password
    ] ++ (stdenv.lib.optionals stdenv.isDarwin [
      darwin.cf-private
      darwin.apple_sdk.frameworks.CoreServices
    ]);
    shellHook = ''
      function op {
        if [ "$1" == "signin" ]; then
          eval $(command op "$@")
        else
          command op "$@"
        fi
      }
    '';
  }
