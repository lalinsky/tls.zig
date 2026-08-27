#!/bin/sh
set -eu

output_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

make_request() {
    name=$1
    subject=$2
    openssl ecparam -name prime256v1 -genkey -noout -out "$work_dir/$name.key"
    openssl req -new -sha256 -key "$work_dir/$name.key" \
        -out "$work_dir/$name.csr" -subj "/CN=$subject"
}

sign_request() {
    name=$1
    issuer=$2
    serial=$3
    extensions=$4
    printf '%s\n%s\n' '[test_extensions]' "$extensions" >"$work_dir/$name.ext"
    database_dir="$work_dir/database-$name"
    mkdir -p "$database_dir/newcerts"
    : >"$database_dir/index"
    printf '%02x\n' "$serial" >"$database_dir/serial"
    printf '%s\n' \
        '[ ca ]' \
        'default_ca = test_ca' \
        '[ test_ca ]' \
        "database = $database_dir/index" \
        "new_certs_dir = $database_dir/newcerts" \
        "serial = $database_dir/serial" \
        'default_md = sha256' \
        'policy = any_name' \
        'unique_subject = no' \
        '[ any_name ]' \
        'commonName = supplied' >"$database_dir/openssl.cnf"
    openssl ca -batch -notext -config "$database_dir/openssl.cnf" \
        -cert "$work_dir/$issuer.pem" -keyfile "$work_dir/$issuer.key" \
        -startdate 260101000000Z -enddate 491231235959Z \
        -extensions test_extensions -extfile "$work_dir/$name.ext" \
        -in "$work_dir/$name.csr" -out "$work_dir/$name.pem" >/dev/null 2>&1
}

leaf_extensions() {
    name=$1
    printf '%s\n' \
        'basicConstraints=critical,CA:FALSE' \
        'keyUsage=critical,digitalSignature' \
        'extendedKeyUsage=serverAuth' \
        "subjectAltName=DNS:$name"
}

make_request root 'tls.zig test root'
openssl req -new -x509 -sha256 -key "$work_dir/root.key" \
    -subj '/CN=tls.zig test root' -days 1 -out "$work_dir/bootstrap.pem"
cp "$work_dir/root.key" "$work_dir/bootstrap.key"
sign_request root bootstrap 1 "$(printf '%s\n' \
    'basicConstraints=critical,CA:TRUE,pathlen:3' \
    'keyUsage=critical,keyCertSign,cRLSign')"

make_request attacker_leaf attacker.test
sign_request attacker_leaf root 2 "$(leaf_extensions attacker.test)"

make_request forged_leaf victim.test
sign_request forged_leaf attacker_leaf 3 "$(leaf_extensions victim.test)"

make_request intermediate 'tls.zig test intermediate'
sign_request intermediate root 4 "$(printf '%s\n' \
    'basicConstraints=critical,CA:TRUE,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign')"

make_request valid_leaf valid.test
sign_request valid_leaf intermediate 5 "$(leaf_extensions valid.test)"

make_request pinned_leaf pinned.test
openssl req -new -x509 -sha256 -key "$work_dir/pinned_leaf.key" \
    -subj '/CN=pinned.test' -days 1 -out "$work_dir/pinned_bootstrap.pem"
cp "$work_dir/pinned_leaf.key" "$work_dir/pinned_bootstrap.key"
sign_request pinned_leaf pinned_bootstrap 6 "$(leaf_extensions pinned.test)"

make_request eku_intermediate 'tls.zig client-only intermediate'
sign_request eku_intermediate root 7 "$(printf '%s\n' \
    'basicConstraints=critical,CA:TRUE,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign' \
    'extendedKeyUsage=clientAuth')"

make_request eku_leaf eku.test
sign_request eku_leaf eku_intermediate 8 "$(leaf_extensions eku.test)"

make_request subordinate_intermediate 'tls.zig subordinate intermediate'
sign_request subordinate_intermediate intermediate 9 "$(printf '%s\n' \
    'basicConstraints=critical,CA:TRUE,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign')"

make_request path_leaf path.test
sign_request path_leaf subordinate_intermediate 10 "$(leaf_extensions path.test)"

make_request constrained_intermediate 'tls.zig constrained intermediate'
sign_request constrained_intermediate root 11 "$(printf '%s\n' \
    'basicConstraints=critical,CA:TRUE,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign' \
    'nameConstraints=critical,permitted;DNS:.allowed.test,excluded;DNS:.blocked.allowed.test')"

make_request allowed_leaf service.allowed.test
sign_request allowed_leaf constrained_intermediate 12 "$(leaf_extensions service.allowed.test)"

make_request denied_leaf x.blocked.allowed.test
sign_request denied_leaf constrained_intermediate 13 "$(leaf_extensions x.blocked.allowed.test)"

for certificate in \
    root attacker_leaf forged_leaf intermediate valid_leaf pinned_leaf \
    eku_intermediate eku_leaf subordinate_intermediate path_leaf \
    constrained_intermediate allowed_leaf denied_leaf
do
    cp "$work_dir/$certificate.pem" "$output_dir/$certificate.pem"
done
