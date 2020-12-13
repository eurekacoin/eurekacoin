## Set env var

```

export SIGNER=erkdev
export VERSION=0.17.5

```

## linux

```

sudo eurekacoin/contrib/gitian-build-linux.py ${SIGNER} ${VERSION} --build --docker -j3

sudo ./bin/gsign --signer ${SIGNER} --release ${VERSION}-linux-unsigned --destination ../gitian.sigs/ ../eurekacoin/contrib/gitian-descriptors/gitian-linux.yml

./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-linux-unsigned ../eurekacoin/contrib/gitian-descriptors/gitian-linux.yml


```

## windows

```

sudo eurekacoin/contrib/gitian-build-windows.py ${SIGNER} ${VERSION} --build --docker -j3

sudo ./bin/gsign --signer ${SIGNER} --release ${VERSION}-windows-unsigned --destination ../gitian.sigs/ ../eurekacoin/contrib/gitian-descriptors/gitian-windows.yml

./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-windows-unsigned ../eurekacoin/contrib/gitian-descriptors/gitian-windows.yml

```

## mac

```

sudo eurekacoin/contrib/gitian-build-osx.py ${SIGNER} ${VERSION} --build --docker -j3

sudo ./bin/gsign --signer ${SIGNER} --release ${VERSION}-osx-unsigned --destination ../gitian.sigs/ ../eurekacoin/contrib/gitian-descriptors/gitian-osx.yml

./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-osx-unsigned ../eurekacoin/contrib/gitian-descriptors/gitian-osx.yml


```


