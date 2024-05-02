# RUVCKR

This is an Ruvchain-go v0.4 build that re-adds tunnel routing/crypto-key routing (CKR) support. Edit section FeaturesConfig in your `ruvchain.conf` like this:

```
FeaturesConfig:
{
  TunnelRouting: {
    Enable: true
    IPv4RemoteSubnets: {
      "a.a.a.a/a": remotepublickey
    }
    IPv6RemoteSubnets: {
      "b::b/b": remotepublickey
    }
  }
}
```

See [manual](https://github.com/ruvcoindev/ruvckr/wiki/Settings-for-ruvckr-to-access-the-Internet-from-a-remote-server) for internet connection sharing through a remote server.

Then use Go 1.18 to build and run:
```
go build -o ruvchain ./cmd/ruvchain
./ruvchain -useconffile ...
```

... or generate an iOS framework with:

```
./contrib/mobile/build -i
```

... or generate an Android AAR bundle with:

```
./contrib/mobile/build -a
```

The main change from the old tunnel routing/CKR support in v0.3 is that you don't need to specify source subnets. Filtering will automatically be applied based on your remote subnets, therefore you'll need to specify the correct remote subnets on both sides.
