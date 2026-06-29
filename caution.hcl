enclave "default" {
  build {
    app_sources = [
      "https://codeberg.org/caution/demo-pq-enclave-binding"
    ]
  }

  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }

    http {
      domain = "pq-ceremony.kobl.one"
      port = 8080
    }
  }

  unit "default" {
    command = "PQ_SUBKEYS_AUTH=30 /app/pq-ceremony --bind 0.0.0.0:8080 --root-ca /etc/pq/aws_nitro_root.der"
  }
}
