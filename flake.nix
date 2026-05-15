{
  description = "CVE-2026-42945 Nginx-Rift — Nix + Podman build (replaces docker-compose)";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # ---------------------------------------------------------------------------
        # Fetch the exact vulnerable nginx commit used by Nginx-Rift (Dockerfile:
        #   git checkout 98fc3bb78)
        # ---------------------------------------------------------------------------
        nginxSrc = pkgs.fetchgit {
          url  = "https://github.com/nginx/nginx.git";
          rev  = "98fc3bb78";
          hash = "sha256-1x3oF9PeDUrWlF4EOQgzyt2/jsGIp3OUWYU86RUHRww=";
        };

        # ---------------------------------------------------------------------------
        # Build nginx from source with identical flags to env/Dockerfile
        # ---------------------------------------------------------------------------
        vulnerableNginx = pkgs.stdenv.mkDerivation {
          pname   = "nginx-cve-2026-42945";
          version = "98fc3bb7";
          src     = nginxSrc;

          nativeBuildInputs = with pkgs; [ gnumake pkg-config perl ];
          buildInputs       = with pkgs; [ pcre2 openssl zlib ];

          configurePhase = ''
            runHook preConfigure
            ./auto/configure \
              --builddir=build \
              --with-cc-opt="-g -O2 -fno-omit-frame-pointer -fPIE" \
              --with-ld-opt="-Wl,-z,relro -Wl,-z,now -pie" \
              --with-http_ssl_module \
              --with-http_v2_module
            runHook postConfigure
          '';

          buildPhase   = "make -j$NIX_BUILD_CORES";

          installPhase = ''
            mkdir -p $out/bin
            cp build/nginx $out/bin/nginx
          '';
        };

        # ---------------------------------------------------------------------------
        # /etc files — fakeNss lacks 'nogroup' which nginx needs by default
        # ---------------------------------------------------------------------------
        etcFiles = pkgs.runCommand "etc-nginx-rift" {} ''
          mkdir -p $out/etc
          printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n' \
            > $out/etc/passwd
          printf 'root:x:0:\nnobody:x:65534:\nnogroup:x:65534:\n' \
            > $out/etc/group
          printf 'passwd: files\ngroup: files\nhosts: dns files\n' \
            > $out/etc/nsswitch.conf
        '';

        # ---------------------------------------------------------------------------
        # Embed env/* into the Nix store so the image is fully reproducible
        # ---------------------------------------------------------------------------
        nginxConf = pkgs.writeText "nginx.conf" (builtins.readFile ./env/nginx.conf);
        serverPy  = pkgs.writeText "server.py"  (builtins.readFile ./env/server.py);

        # Container entrypoint:
        #   1. Create runtime dirs expected by nginx.conf (-p /app)
        #   2. Start the Python backend (delay server)
        #   3. Exec nginx with ASLR disabled via setarch -R
        entrypoint = pkgs.writeShellScript "entrypoint" ''
          mkdir -p /app/logs /app/tmp
          # world-writable /tmp so nginx worker (nobody) can create files there
          mkdir -p /tmp && chmod 1777 /tmp
          ${pkgs.python3}/bin/python3 ${serverPy} &>/dev/null &
          exec ${pkgs.util-linux}/bin/setarch x86_64 -R \
            ${vulnerableNginx}/bin/nginx -p /app -c ${nginxConf}
        '';

        # ---------------------------------------------------------------------------
        # OCI image — equivalent to `docker compose build` in the original setup
        # ---------------------------------------------------------------------------
        vulnerableImage = pkgs.dockerTools.buildLayeredImage {
          name = "nginx-rift";
          tag  = "vulnerable";

          contents = with pkgs; [
            vulnerableNginx
            python3
            util-linux   # provides setarch(1) for ASLR disabling
            bash
            coreutils
            gdb
            etcFiles     # /etc/passwd + /etc/group with nobody + nogroup
          ];

          config = {
            Cmd          = [ "${entrypoint}" ];
            ExposedPorts = { "19321/tcp" = {}; };
            Labels = {
              "org.opencontainers.image.title"   = "CVE-2026-42945 nginx-rift vulnerable image";
              "org.opencontainers.image.revision" = "98fc3bb78";
            };
          };
        };

      in {
        packages = {
          dockerImage = vulnerableImage;
          default     = vulnerableImage;
        };
      }
    );
}
