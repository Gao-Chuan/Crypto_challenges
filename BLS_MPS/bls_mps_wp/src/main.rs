extern crate bls12_381;
extern crate sha2;

use std::str;
use std::net::TcpStream;
use std::io::{Read, Write};

use bls12_381::{Scalar, G1Affine, G1Projective, G2Affine};
use hex::{encode, decode_to_slice};
use rand::Rng;
use sha2::{Sha512, Digest};


fn keygen() -> (G1Affine, Scalar) {    
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
    let mut result = [0; 64];
    result[..].clone_from_slice(&tmp[..]);
    let hm = Scalar::from_bytes_wide(&result);

    let h_point = G2Affine::from(G2Affine::generator() * hm);

    return h_point;
}

fn main(){
    match TcpStream::connect("qcloud-gd-1.loli.network:10086") {
        Ok(mut stream) =>{
            let mut data = [0 as u8; 50];
            match stream.read(&mut data) {
                Ok(_) => {
                    println!("{}", str::from_utf8(&data).unwrap());
                },
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                }
            }
            let mut raw_pk = [0 as u8; 100];
            let mut pk_bytes = [0 as u8; 48];
            match stream.read(&mut raw_pk) {
                Ok(_size) => {
                    println!("{}", str::from_utf8(&raw_pk).unwrap());
                    let pkstr = str::from_utf8(&raw_pk[..96]).unwrap();
                    decode_to_slice(&pkstr, &mut pk_bytes).unwrap();
                },
                Err(_) => {
                    println!("\nAn error occurred.\n");
                }
            }
            let pk = G1Affine::from_compressed(&pk_bytes).unwrap();
            
            let msg = "admin".to_string();
            let (mut pk2, beta) = keygen();
            pk2 = G1Affine::from(G1Projective::from(pk2) - pk);

            let mut data = [0 as u8; 33];
            match stream.read(&mut data) {
                Ok(_) => {
                    println!("{}", str::from_utf8(&data).unwrap());
                },
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                }
            }
            println!("{}", encode(pk2.to_compressed()));
            stream.write(encode(pk2.to_compressed()).as_bytes()).unwrap();

            let mut data = [0 as u8; 80];
            match stream.read(&mut data) {
                Ok(_) => {
                    println!("{}", str::from_utf8(&data).unwrap());
                },
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                }
            }

            stream.write(b"2").unwrap();

            let mut data = [0 as u8; 40];
            match stream.read(&mut data) {
                Ok(_) => {
                    println!("{}", str::from_utf8(&data).unwrap());
                },
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                }
            }
            
            let signature = G2Affine::from(hash(&msg) * beta);
            println!("{}", encode(signature.to_compressed()));
            stream.write(encode(signature.to_compressed()).as_bytes()).unwrap();
            

            let mut data = [0 as u8; 1024];
            match stream.read(&mut data){
                Ok(_size) => {
                    println!("{}", str::from_utf8(&data).unwrap());
                },
                Err(_) => {
                    println!("error on get flag");
                }
            }
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    
}