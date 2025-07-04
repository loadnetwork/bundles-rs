//! Deep‑hash algorithm as described in ANS‑104 / Bundlr spec.
//! Uses SHA‑384 (not SHA‑256) exactly like the reference JS SDK.

use sha2::{Digest, Sha384};

#[derive(Debug, Clone)]
pub enum DeepHash<'a> {
    Blob(&'a [u8]),
    List(Vec<DeepHash<'a>>),
}

fn sha384(data: &[u8]) -> [u8; 48] {
    Sha384::digest(data).into()
}

pub fn deep_hash_sync(item: &DeepHash<'_>) -> [u8; 48] {
    match item {
        DeepHash::Blob(bytes) => deep_hash_blob(bytes),
        DeepHash::List(list) => deep_hash_list(list),
    }
}

fn deep_hash_blob(data: &[u8]) -> [u8; 48] {
    let tag = format!("blob{}", data.len());
    let hash_tag = sha384(tag.as_bytes());
    let hash_dat = sha384(data);

    let mut concat = Vec::with_capacity(96);
    concat.extend_from_slice(&hash_tag);
    concat.extend_from_slice(&hash_dat);
    sha384(&concat)
}

fn deep_hash_list(list: &[DeepHash<'_>]) -> [u8; 48] {
    let tag = format!("list{}", list.len());
    let mut acc = sha384(tag.as_bytes());

    for child in list {
        let child_hash = deep_hash_sync(child);

        let mut pair = Vec::with_capacity(96);
        pair.extend_from_slice(&acc);
        pair.extend_from_slice(&child_hash);

        acc = sha384(&pair);
    }
    acc
}

#[cfg(test)]
mod deep_hash_erlan_ported_tests {
    use super::*;
    use sha2::{Digest, Sha384};

    fn sha(b: &[u8]) -> [u8; 48] {
        Sha384::digest(b).into()
    }

    fn dh_blob(v: &[u8]) -> [u8; 48] {
        let tag = format!("blob{}", v.len());
        sha(&[sha(tag.as_bytes()).as_slice(), sha(v).as_slice()].concat())
    }

    /* -------------------------------------------------------------- */
    /* hash_test/0 – same structure & manual digest as Erlang example */
    /* -------------------------------------------------------------- */
    #[test]
    fn deep_hash_reference_vector() {
        let v1 = [0u8; 32];
        let v2 = [1u8; 32];
        let v3 = [2u8; 32];
        let v4 = [3u8; 32];

        // manual digest chain (exact Erlang steps)
        let h1 = dh_blob(&v1);
        let h2 = dh_blob(&v2);
        let h3 = dh_blob(&v3);
        let h4 = dh_blob(&v4);

        let h_sub_tag = sha(b"list2");
        let h_sub_acc = sha(&[h_sub_tag.as_slice(), h2.as_slice()].concat());
        let h_sub = sha(&[h_sub_acc.as_slice(), h3.as_slice()].concat());

        let h_tag = sha(b"list3");
        let h_acc_1 = sha(&[h_tag.as_slice(), h1.as_slice()].concat());
        let h_acc_2 = sha(&[h_acc_1.as_slice(), h_sub.as_slice()].concat());
        let expected = sha(&[h_acc_2.as_slice(), h4.as_slice()].concat());

        // run Rust deep‑hash
        let deep = DeepHash::List(vec![
            DeepHash::Blob(&v1),
            DeepHash::List(vec![DeepHash::Blob(&v2), DeepHash::Blob(&v3)]),
            DeepHash::Blob(&v4),
        ]);
        assert_eq!(expected, deep_hash_sync(&deep));
    }

    /* -------------------------------------------------------------- */
    /* hash_empty_list_test/0 */
    /* -------------------------------------------------------------- */
    #[test]
    fn deep_hash_empty_list() {
        let expected = sha(b"list0");
        let got = deep_hash_sync(&DeepHash::List(vec![]));
        assert_eq!(expected, got);
    }

    /* -------------------------------------------------------------- */
    /* hash_uniqueness_test/0 – structural differences */
    /* -------------------------------------------------------------- */
    #[test]
    fn deep_hash_uniqueness() {
        let a = DeepHash::Blob(b"a");
        let b = DeepHash::Blob(b"b");
        let c = DeepHash::Blob(b"c");
        let d = DeepHash::Blob(b"d");
        let e = DeepHash::Blob(b"e");

        assert_ne!(
            deep_hash_sync(&DeepHash::List(vec![a.clone()])),
            deep_hash_sync(&DeepHash::List(vec![DeepHash::List(vec![a.clone()])]))
        );

        assert_ne!(
            deep_hash_sync(&DeepHash::List(vec![a.clone(), b.clone()])),
            deep_hash_sync(&DeepHash::List(vec![b.clone(), a.clone()]))
        );

        assert_ne!(
            deep_hash_sync(&DeepHash::List(vec![a.clone(), DeepHash::Blob(&[])])),
            deep_hash_sync(&DeepHash::List(vec![a.clone()]))
        );

        assert_ne!(
            deep_hash_sync(&DeepHash::List(vec![a.clone(), b.clone()])),
            deep_hash_sync(&DeepHash::List(vec![DeepHash::List(vec![a.clone()]), b.clone()]))
        );

        assert_ne!(
            deep_hash_sync(&DeepHash::List(vec![
                a.clone(),
                DeepHash::List(vec![b.clone(), c.clone()])
            ])),
            deep_hash_sync(&DeepHash::List(vec![a.clone(), b.clone(), c.clone()]))
        );

        assert_ne!(
            deep_hash_sync(&DeepHash::List(vec![
                a.clone(),
                DeepHash::List(vec![b.clone(), c.clone()]),
                DeepHash::List(vec![d.clone(), e.clone()])
            ])),
            deep_hash_sync(&DeepHash::List(vec![
                a.clone(),
                DeepHash::List(vec![b.clone(), c.clone(), d.clone(), e.clone()])
            ]))
        );

        assert_ne!(
            deep_hash_sync(&DeepHash::List(vec![
                a.clone(),
                DeepHash::List(vec![b.clone()]),
                c.clone(),
                d.clone()
            ])),
            deep_hash_sync(&DeepHash::List(vec![a, DeepHash::List(vec![b, c]), d]))
        );
    }
}
