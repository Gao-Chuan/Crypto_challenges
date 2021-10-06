extern crate bls12_381;
extern crate sha2;

use std::{thread, str};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use std::fs;

use bls12_381::{pairing, Scalar, G1Affine, G2Affine};
use hex::{encode, decode_to_slice};
use rand::Rng;
use sha2::{Sha512, Digest};

fn keygen() -> (G1Affine, Scalar) {    
    // check compressed. Passed
    // let alice_compressed = hex::encode(alice.to_compressed());
    // let mut alice_cp = [0 as u8; 48];
    // hex::decode_to_slice(alice_compressed, &mut alice_cp).unwrap();
    // println!("{}", G1Affine::from_compressed(&alice_cp).unwrap());

    let random_bytes1 = rand::thread_rng().gen::<[u8; 32]>();
    let random_bytes2 = rand::thread_rng().gen::<[u8; 32]>();
    let mut random_bytes = [0; 64];
    random_bytes[..32].clone_from_slice(&random_bytes1);
    random_bytes[32..].clone_from_slice(&random_bytes2);

    let sk = Scalar::from_bytes_wide(&random_bytes);
    let pk = G1Affine::from(G1Affine::generator() * sk);

    return (pk, sk);
}

fn hash(msg: &String) -> G2Affine{
    let mut hasher = Sha512::new();
    hasher.update(msg);
    let tmp = hasher.finalize();
    // let result: [u8; 64] = result[..].try_into().expect("Wrong length");
    let mut result = [0; 64];
    result[..].clone_from_slice(&tmp[..]);
    let hm = Scalar::from_bytes_wide(&result);

    let h_point = G2Affine::from(G2Affine::generator() * hm);

    return h_point;
}

fn sign(sk: &Scalar, msg: &String) -> G2Affine {
    let h_point = hash(msg);
    let signature = G2Affine::from(h_point * sk);

    return signature;
}

fn verify(pks: &[&G1Affine], m: &String, sig: &G2Affine) -> bool {
    return pairing(&pks[0], &hash(m)) + pairing(&pks[1], &hash(m))
                     == pairing(&G1Affine::generator(), sig);
}

fn handle_client(mut stream: TcpStream){
    stream.write(b"\nWelcome to mps system. This is my public key:>>\n").unwrap();
    let (pk, sk) = keygen();
    let pk_hex = encode(pk.to_compressed());
    stream.write(pk_hex.as_bytes()).unwrap();

    stream.write(b"\nShow me your hex public key:>>\n").unwrap();
    let mut raw_user_pk = [0 as u8; 100];
    let mut user_pk_bytes = [0 as u8; 48];
    match stream.read(&mut raw_user_pk) {
        Ok(_size) => {
            let pkstr = str::from_utf8(&raw_user_pk[..96]).unwrap();
            decode_to_slice(&pkstr, &mut user_pk_bytes).unwrap();
        },
        Err(_) => {
            println!("\nAn error occurred, terminating connection with {}\n", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
        }
    }
    let user_pk = G1Affine::from_compressed(&user_pk_bytes).unwrap();

    let menu = b"\n1. Request a signature(msg within 1024 bytes)\r\n2. Convince me you are admin.\n";
    for _i in 0..2{
        let mut choice = [0 as u8; 2];
        stream.write(menu).unwrap();
        stream.read(&mut choice).unwrap();
        if choice[0] == '1' as u8{
            stream.write(b"Give me your msg:>>").unwrap();
            let mut data = [0 as u8; 1024];
            let mut data_str = "";
            match stream.read(&mut data){
                Ok(size) => {
                    data_str = str::from_utf8(&data[..size]).unwrap();
                    stream.write(b"Your message is:>>").unwrap();
                    stream.write(data_str.as_bytes()).unwrap();
                    if data_str.contains("admin"){
                        stream.write(b"No you are not.\n").unwrap();
                        stream.shutdown(Shutdown::Both).unwrap();
                    }
                },
                Err(_) => {
                    println!("\nAn error occurred, terminating connection with {}\n", stream.peer_addr().unwrap());
                    stream.shutdown(Shutdown::Both).unwrap();
                }
            }
            let sig = sign(&sk, &data_str.to_string());
            stream.write(b"The signature is:>>").unwrap();
            stream.write(encode(sig.to_compressed()).as_bytes()).unwrap();
        } else if choice[0] == '2' as u8{
            stream.write(b"Show me your signature of admin:>>").unwrap();
            let mut sig = [0 as u8; 200];
            match stream.read(&mut sig){
                Ok(_size) => {
                    let mut sig_bt = [0 as u8; 96];
                    decode_to_slice(&str::from_utf8(&sig[..192]).unwrap(), &mut sig_bt).unwrap();
                    let sig = G2Affine::from_compressed(&sig_bt).unwrap();
                    let pks = [&pk, &user_pk];
                    if verify(&pks, &"admin".to_string(), &sig){
                        let flag = fs::read_to_string("flag.txt").unwrap();
                        stream.write(flag.as_bytes()).unwrap();
                        return;
                    } else{
                        stream.write(b"\n:(\n").unwrap();
                        stream.shutdown(Shutdown::Both).unwrap();
                    }
                },
                Err(_) => {
                    println!("\nAn error occurred, terminating connection with {}\n", stream.peer_addr().unwrap());
                    stream.shutdown(Shutdown::Both).unwrap();
                }
            }
        } else{
            println!("\nAn error occurred, terminating connection with {}\n", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
        }

    }
}


fn main() {
    let listener = TcpListener::bind("0.0.0.0:10086").unwrap();
    println!("Server listening on port 10086");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    // connection succeeded
                    handle_client(stream)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    drop(listener);
}