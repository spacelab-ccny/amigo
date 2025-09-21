extern crate alloc;

use alloc::string::String;
use criterion::{criterion_group, criterion_main, Criterion};

use dark_matter::member::Member;

fn setup_10(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 10;
    let group_capacity = 16;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[9].clone();
    let tmp2 = members[2].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
     
    
    let mut group_bench = c.benchmark_group("setup_10");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks


    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));
    group_bench.finish();

}

fn setup_25(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 25;
    let group_capacity = 32;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[24].clone();
    let tmp2 = members[10].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
     
    
    let mut group_bench = c.benchmark_group("setup_25");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks


    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));
    group_bench.finish();

}

fn setup_50(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 50;
    let group_capacity = 64;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[49].clone();
    let tmp2 = members[10].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    
    let mut group_bench = c.benchmark_group("setup_50");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks

    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));

    group_bench.finish();

}

fn setup_75(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 75;
    let group_capacity = 128;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[74].clone();
    let tmp2 = members[10].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
     
    
    let mut group_bench = c.benchmark_group("setup_75");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks


    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));
    group_bench.finish();

}

fn setup_100(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 100;
    let group_capacity = 128;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[99].clone();
    let tmp2 = members[10].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    

    let mut group_bench = c.benchmark_group("setup_100");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks

    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));

    group_bench.finish();

}

fn setup_125(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 125;
    let group_capacity = 128;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[124].clone();
    let tmp2 = members[10].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
     
    
    let mut group_bench = c.benchmark_group("setup_125");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks


    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));
    group_bench.finish();

}

fn setup_150(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 150;
    let group_capacity = 256;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[149].clone();
    let tmp2 = members[10].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
     
    
    let mut group_bench = c.benchmark_group("setup_150");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks


    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));
    group_bench.finish();

}

fn setup_175(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 175;
    let group_capacity = 256;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[174].clone();
    let tmp2 = members[10].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
     
    
    let mut group_bench = c.benchmark_group("setup_175");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks


    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));
    group_bench.finish();

}

fn setup_200(c: &mut Criterion) {
    let group_name = String::from("test");
    let size = 200;
    let group_capacity = 256;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[199].clone();
    let tmp2 = members[10].clone();
    // generate different size messages
    let byte_vec_250: Vec<u8> = (0..250).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_250, tmp_nonce_0, _message_counter) = tmp1.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    let byte_vec_2_mb: Vec<u8> = (0..2000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_2_mb, tmp_nonce_1, _message_counter) = tmp1.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    let byte_vec_10_mb: Vec<u8> = (0..10000000).map(|i| (i % 128) as u8).collect();
    let (tmp_ciphertext_10_mb, tmp_nonce_2, message_counter) = tmp1.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    
    let mut group_bench = c.benchmark_group("setup_200");
    group_bench.sample_size(1000); // Specify sample size for all benchmarks


    group_bench.bench_function("add_to_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut member = tmp1.clone();
        let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    }));
    group_bench.bench_function("remove_from_group_time", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
        applying_member.apply_blank_message(group_name.clone(), blank_message);
    }));
    group_bench.bench_function("key_refresh", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let mut applying_member = tmp2.clone();
        let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
        applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    }));
    group_bench.bench_function("encrypt_group_message_size_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();   
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_250.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_2_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("encrypt_group_message_size_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();  
        let (_ciphertext, _nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec_10_mb.clone(), group_name.clone());
    }));
    group_bench.bench_function("decrypt_group_message_250B", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_250.clone(), group_name.clone(), tmp_nonce_0, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_2MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_2_mb.clone(), group_name.clone(), tmp_nonce_1, message_counter);
    }));
    group_bench.bench_function("decrypt_group_message_10MB", |b| b.iter(|| {
        // Code to benchmark goes here
        let mut initiating_member = tmp1.clone();
        let _plaintext = initiating_member.decrypt_application_message(tmp_ciphertext_10_mb.clone(), group_name.clone(), tmp_nonce_2, message_counter);
    }));

    group_bench.finish();

}
// criterion_group!(benches,setup_200);
criterion_group!(benches,setup_10, setup_25, setup_50, setup_75, setup_100, setup_125, setup_150, setup_175, setup_200);
criterion_main!(benches);