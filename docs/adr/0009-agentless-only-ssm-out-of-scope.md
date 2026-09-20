# 0009. Agentless only, SSM out of scope

Date: 2026-09-20

## Status

Accepted

## Context

Zanskar's promise is that nothing needs to be installed on a target. Some cloud access mechanisms
offer better security properties but require an agent. AWS Systems Manager Session Manager is the
most tempting: it needs no inbound ports and no credentials, but it requires the SSM agent on the
instance and an IAM instance profile.

## Decision

Zanskar connects to targets only over protocols that a stock operating system already speaks:

- SSH for Linux, BSD, network appliances, and Windows where OpenSSH Server is enabled.
- RDP for Windows desktops and xrdp on Linux.
- VNC for Linux and other desktops.
- WinRM for Windows command-line access where SSH is not enabled.

EC2 Instance Connect is permitted as a credential type because it uses the standard SSH server and
a small package that ships in Amazon Linux and Ubuntu AMIs by default. Zanskar pushes an ephemeral
public key through the AWS API and connects over SSH within the sixty-second window.

SSM Session Manager is out of scope. It requires an agent, which contradicts the product promise,
and a Zanskar deployment that depends on it would silently stop working on instances where the
agent is absent.

## Consequences

- Targets need an inbound path from the gateway on 22, 3389, 5900, or 5985/5986. Deployment
  guidance covers security groups and firewall rules that allow only the gateway.
- Windows targets must have either OpenSSH Server or WinRM enabled. WinRM is on by default on
  Windows Server, so most fleets need no change.
- Instance Connect needs `ec2-instance-connect:SendSSHPublicKey` in the enrollment role
  (ADR 0011). It is optional.
- If a future version adds SSM support it will be an explicit, separately documented feature with
  its own ADR, not a silent fallback.
