# Risky Chat

Risky Chat is a global chatroom implemented as a web
application, for the [Cyber Security Base 2020 course][course].

Users identify themselves by a unique name which expires after the
user has not posted anything in 5 minutes, making a nice tradeoff
between transient identity and anonymity, and being able to ensure two
sequential posts are from the same person.

## Important security note

This application has intentionally designed security risks, including
one very major one: being implemented in C without using any tools or
checks to ensure secure memory management. Avoid this.

## Why C?

It's the one time I can write an incredibly insecure server in C with
a good conscience. Ignoring the numerous security risks it raises, C
is a really fun programming language to use.

## Building and running

Requirements: a C compiler and a POSIX.1-2001 compliant system
(e.g. Linux).

Just compile [riskychat.c](riskychat.c) into an executable. Basic
example:

```
cc -o riskychat riskychat.c
./riskychat
```

Risky Chat also compiles with TCC, so you can run it like a script if
you have [tcc][tcc]:

```
tcc -run riskychat.c
```

For development, I use the following incantation:

```
musl-gcc -static -std=c89 -Wall -Werror -Wpedantic -fanalyzer -O3 -o riskychat riskychat.c
./riskychat
```

## License

This software is distributed under the [GNU AGPL 3.0][license]
license. Though I really recommend against using it, it's very
insecure.

[course]: https://cybersecuritybase.mooc.fi/
[license]: LICENSE.md
[tcc]: https://bellard.org/tcc/
