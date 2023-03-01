module mokshya::merkle_nft_distributor{
    use std::signer;
    use aptos_std::aptos_hash;
    use mokshya::merkle_proof::{Self};
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::account;
    use aptos_token::token::{Self};
    use std::string::{Self,String};
    use aptos_std::type_info;
    use aptos_std::table::{Self, Table};
    use std::bcs;
    use std::vector;

    struct DistributionDetails has key {
        merkle_root: vector<u8>,
        creator_address:address, 
        distribution_event: EventHandle<CreateDistributionEvent>,
    }
    struct ClaimDistribution has key {
        claimers: Table<address,u64>,
        paused: bool,
        claim_event: EventHandle<ClaimDistributionEvent>,
    }
    struct ResourceInfo has key {
            source: address,
            resource_cap: account::SignerCapability
    }
    struct CreateDistributionEvent has drop, store {
        distributor: address,
        creator_address: address,
        merkle_root: vector<u8>
    }
    struct ClaimDistributionEvent has drop, store {
        claimer: address,
        claimed: u64,
        creator_address:address, 
    }
    const COINTYPE_MISMATCH:u64=0;
    const DISTRIBUTION_EXISTS:u64=1;
    const INVALID_PROOF:u64=2;
    const AlREADY_CLAIMED:u64=2;
    const INVALID_SIGNER:u64=3;
    const PAUSED:u64=4;
    const CLAIM_LIMIT_EXCEED:u64=5;

    public entry fun init_distribution(distributor: &signer,merkle_root: vector<u8>,seeds: vector<u8>,creator_address:address)acquires DistributionDetails {
        let (resource, resource_cap) = account::create_resource_account(distributor, seeds);
        let resource_signer_from_cap = account::create_signer_with_capability(&resource_cap);
        let resource_address = signer::address_of(&resource);
        assert!(!exists<DistributionDetails>(resource_address),DISTRIBUTION_EXISTS);
        move_to<ResourceInfo>(&resource_signer_from_cap, ResourceInfo{resource_cap: resource_cap, source: signer::address_of(distributor)});
        move_to<DistributionDetails>(&resource_signer_from_cap, DistributionDetails{
            merkle_root,
            creator_address:creator_address, 
            distribution_event: account::new_event_handle<CreateDistributionEvent>(&resource_signer_from_cap),
        });
        token::opt_in_direct_transfer(&resource_signer_from_cap,true);
        move_to<ClaimDistribution>(&resource_signer_from_cap, ClaimDistribution{
            claimers: table::new<address,u64>(),
            paused: false,
            claim_event: account::new_event_handle<ClaimDistributionEvent>(&resource_signer_from_cap),
        });
        token::opt_in_direct_transfer(&resource_signer_from_cap,true);
        let records = borrow_global_mut<DistributionDetails>(resource_address);
        event::emit_event(&mut records.distribution_event,CreateDistributionEvent {
                distributor:signer::address_of(distributor),
                creator_address:creator_address, 
                merkle_root
            },
        );
    }
    public entry fun claim_distribution(
        claimer: &signer,
        resource_account:address,
        proof: vector<vector<u8>>,
        collection_name: String,
        token_name: String,
        property_version: u64,
        claim_limit: u64
        )acquires DistributionDetails,ResourceInfo,ClaimDistribution {
        let claimer_addr = signer::address_of(claimer);
        let resource_data = borrow_global<ResourceInfo>(resource_account);
        let resource_signer_from_cap = account::create_signer_with_capability(&resource_data.resource_cap);
        let distributor_details = borrow_global<DistributionDetails>(resource_account);
        let claim_details = borrow_global_mut<ClaimDistribution>(resource_account);
        assert!(claim_details.paused == false, PAUSED);
        let leafvec = bcs::to_bytes(&claimer_addr);
        vector::append(&mut leafvec,bcs::to_bytes(&claim_limit));
        assert!(merkle_proof::verify(proof,distributor_details.merkle_root,aptos_hash::keccak256(leafvec)),INVALID_PROOF);
        if (!table::contains(&claim_details.claimers, claimer_addr)) {
             // First time claimming = 0 
            table::add(&mut claim_details.claimers,claimer_addr,0);
        };
        let check_claim_limit = table::borrow_mut(&mut claim_details.claimers, claimer_addr);
        assert!(*check_claim_limit != claim_limit, CLAIM_LIMIT_EXCEED);
        *check_claim_limit = *check_claim_limit + 1;
        let token_id = token::create_token_id_raw(distributor_details.creator_address, collection_name, token_name, property_version);
        token::opt_in_direct_transfer(claimer,true);
        token::direct_transfer(&resource_signer_from_cap,claimer,token_id,1);
        event::emit_event(&mut claim_details.claim_event,ClaimDistributionEvent {
                claimer: claimer_addr,
                claimed: *check_claim_limit,
                creator_address:distributor_details.creator_address, 
            }
        );
    }
    public entry fun withdraw_tokens(
        distributor: &signer,
        resource_account:address,
        collection_name: String,
        token_name: String,
        property_version: u64
        )acquires ResourceInfo,DistributionDetails {
        let resource_data = borrow_global<ResourceInfo>(resource_account);
        let resource_signer_from_cap = account::create_signer_with_capability(&resource_data.resource_cap);
        let distributor_details = borrow_global<DistributionDetails>(resource_account);
        assert!(resource_data.source == signer::address_of(distributor), INVALID_SIGNER);
        let token_id = token::create_token_id_raw(distributor_details.creator_address, collection_name, token_name, property_version);
        token::opt_in_direct_transfer(distributor,true);
        token::direct_transfer(&resource_signer_from_cap,distributor,token_id,1);
    }
    public entry fun update_root(distributor: &signer,resource_account:address,merkle_root:vector<u8>)acquires ResourceInfo,DistributionDetails {
        let resource_data = borrow_global<ResourceInfo>(resource_account);
        assert!(resource_data.source == signer::address_of(distributor), INVALID_SIGNER);
        let distribution_data = borrow_global_mut<DistributionDetails>(resource_account);
        distribution_data.merkle_root = merkle_root;
    }
    public entry fun pause_distribution(distributor: &signer,resource_account:address)acquires ResourceInfo,ClaimDistribution {
        let resource_data = borrow_global<ResourceInfo>(resource_account);
        assert!(resource_data.source == signer::address_of(distributor), INVALID_SIGNER);
        let claim_data = borrow_global_mut<ClaimDistribution>(resource_account);
        claim_data.paused = true;
    }
    public entry fun resume_distribution(distributor: &signer,resource_account:address)acquires ResourceInfo,ClaimDistribution {
        let resource_data = borrow_global<ResourceInfo>(resource_account);
        assert!(resource_data.source == signer::address_of(distributor), INVALID_SIGNER);
        let claim_data = borrow_global_mut<ClaimDistribution>(resource_account);
        claim_data.paused = false;
    }
    #[test_only] 
    use aptos_token::token::{create_collection,create_token_script};
    #[test_only] 
    public fun set_up_test(distributor:&signer,claimer:&signer){
        let distributor_addr = signer::address_of(distributor);
        let claimer_addr = signer::address_of(claimer);
        aptos_framework::account::create_account_for_test(distributor_addr);
        aptos_framework::account::create_account_for_test(claimer_addr);
        create_collection(
            distributor,
            string::utf8(b"Mokshya Collection"),
            string::utf8(b"Collection for Test"),
            string::utf8(b"https://github.com/mokshyaprotocol"),
            2,
            vector<bool>[false, false, false],
        );
        create_token_script(
            distributor,
            string::utf8(b"Mokshya Collection"),
            string::utf8(b"Mokshya Token #1"),
            string::utf8(b"Collection for Test"),
            2,
            5,
            string::utf8(b"mokshya.io"),
            signer::address_of(distributor),
            100,
            0,
            vector<bool>[false, false, false, false, false],
            vector<String>[string::utf8(b"attack"), string::utf8(b"num_of_use")],
            vector<vector<u8>>[bcs::to_bytes<u64>(&10), bcs::to_bytes<u64>(&5)],
            vector<String>[string::utf8(b"u64"), string::utf8(b"u64")]
        );

    }
    #[test(distributor = @0xa11ce, claimer = @0xd4dee0beab2d53f2cc83e567171bd2820e49898130a22622b10ead383e90bd77)]
    fun test_distribute(distributor: &signer,claimer: &signer)acquires DistributionDetails,ClaimDistribution,ResourceInfo{
        // let claimer_addr = signer::address_of(claimer);
        let distributor_addr = signer::address_of(distributor);
        let add1=  x"d4dee0beab2d53f2cc83e567171bd2820e49898130a22622b10ead383e90bd77";
        let add2 = x"5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02";
        let claim_limit:u64 = 1;
        vector::append(&mut add1,bcs::to_bytes(&claim_limit));
        vector::append(&mut add2,bcs::to_bytes(&claim_limit));
        let leaf1 = aptos_hash::keccak256(add1);
        let leaf2 = aptos_hash::keccak256(add2);
        let merkle_root = merkle_proof::find_root(leaf1,leaf2);
        set_up_test(distributor,claimer);
        init_distribution(distributor,merkle_root,b"merkle_distributor",distributor_addr);
        let resource_addr = account::create_resource_address(&distributor_addr, b"merkle_distributor");
        token::transfer_with_opt_in(distributor,distributor_addr,string::utf8(b"Mokshya Collection"),string::utf8(b"Mokshya Token #1"),0,resource_addr,1);
        claim_distribution(claimer,resource_addr,vector[leaf2],string::utf8(b"Mokshya Collection"),string::utf8(b"Mokshya Token #1"),0,claim_limit);
    }
}