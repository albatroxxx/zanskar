# One key pair for every test box. The private key is written to the repo's
# ignored data/ directory; it never enters Terraform state as plaintext output.
resource "tls_private_key" "boxes" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "boxes" {
  key_name   = "${var.name}-boxes"
  public_key = tls_private_key.boxes.public_key_openssh
}

resource "local_sensitive_file" "boxes_key" {
  content         = tls_private_key.boxes.private_key_openssh
  filename        = "${path.module}/../../data/aws-boxes.pem"
  file_permission = "0600"
}

# Windows password decryption needs an RSA key.
resource "tls_private_key" "windows" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "windows" {
  key_name   = "${var.name}-windows"
  public_key = tls_private_key.windows.public_key_openssh
}

resource "local_sensitive_file" "windows_key" {
  content         = tls_private_key.windows.private_key_pem
  filename        = "${path.module}/../../data/aws-windows.pem"
  file_permission = "0600"
}
