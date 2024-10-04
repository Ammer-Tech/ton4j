package org.ton.java.exec;

import org.ton.java.utils.Utils;
import org.ton.java.cell.Cell;
import org.ton.java.cell.CellSlice;
import org.ton.java.address.Address;
import org.ton.java.cell.CellBuilder;
import org.ton.java.tonlib.Tonlib;
import org.ton.java.tonlib.client.TonClient;
import org.ton.java.tonlib.client.TonIO;
import org.ton.java.tonlib.types.BlockIdExt;
import org.ton.java.tonlib.types.MasterChainInfo;
import org.ton.java.tonlib.types.BlockTransactions;
import org.ton.java.tonlib.types.ShortTxId;
import org.ton.java.tonlib.types.*;
import org.ton.java.bitstring.BitString;

import java.util.concurrent.TimeUnit;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileInputStream;

import org.ton.java.exec.UUIDCodec;
import java.util.UUID;
import com.jsoniter.JsonIterator;
import com.jsoniter.output.EncodingMode;
import com.jsoniter.output.JsonStream;
import com.jsoniter.spi.DecodingMode;
import com.jsoniter.spi.JsoniterSpi;
import com.jsoniter.output.JsonStream;

import static java.util.Objects.isNull;

public class Exec {
  private TonClient tonlib;
  private HashSet<String> last_shards;
  private HashMap<String, String> known_contracts;
  private long last_mc_seqno;

  public static Address get_address_by_key (byte key[]) {
    CellBuilder cb = CellBuilder.beginCell ();
    boolean c[] = {false, false, true, true, false};
    cb.storeBits (c);

    CellBuilder cb_code = CellBuilder.beginCell ();
    cb_code.storeBytes (Utils.hexToBytes ("FF0020DD2082014C97BA218201339CBAB19F71B0ED44D0D31FD31F31D70BFFE304E0A4F2608308D71820D31FD31FD31FF82313BBF263ED44D0D31FD31FD3FFD15132BAF2A15144BAF2A204F901541055F910F2A3F8009320D74A96D307D402FB00E8D101A4C8CB1FCB1FCBFFC9ED54"));
    cb.storeRef (cb_code.endCell ());

    CellBuilder cb_data = CellBuilder.beginCell ();
    cb_data.storeInt (0, 32); // seqno
    cb_data.storeInt (0, 32); // subwallet
    cb_data.storeBytes (key);
    cb.storeRef (cb_data.endCell ());

    Cell cell = cb.endCell ();
    return new Address ("0:" + Utils.bytesToHex(cell.hash()));
  }
  private static Cell create_message (byte [] signature, int seqno, int valid_until, String payload, Cell payload_cell, byte key[], Address src, Address dst, long grams) {
    CellBuilder cb = CellBuilder.beginCell ();
    if (signature.length > 0) {
      // 10 - external message
      // 00 - src addr none 
      // 10 - addr-std
      // 0 - not anycast
      boolean []b01 = {true, false, false, false, true, false, false};
      cb.storeBits(b01);
      cb.storeInt (src.wc, 8);
      cb.storeBytes (src.hashPart);
      cb.storeCoins (BigInteger.valueOf(0)); // import fee
      if (seqno == 1) {
        cb.storeBit(true); // has_state
        cb.storeBit(false); // state is inlined
        cb.storeBit(false); // splitdepth
        cb.storeBit(false); // special
        cb.storeBit(true); // code
        cb.storeBit(true); // data
        cb.storeBit(false); // libraries

        CellBuilder cb_code = CellBuilder.beginCell ();
        cb_code.storeBytes (Utils.hexToBytes ("FF0020DD2082014C97BA218201339CBAB19F71B0ED44D0D31FD31F31D70BFFE304E0A4F2608308D71820D31FD31FD31FF82313BBF263ED44D0D31FD31FD3FFD15132BAF2A15144BAF2A204F901541055F910F2A3F8009320D74A96D307D402FB00E8D101A4C8CB1FCB1FCBFFC9ED54"));
        cb.storeRef (cb_code.endCell ());

        CellBuilder cb_data = CellBuilder.beginCell ();
        cb_data.storeInt (0, 32); // seqno
        cb_data.storeInt (0, 32); // subwallet
        cb_data.storeBytes (key);
        cb.storeRef (cb_data.endCell ());
      } else {
        cb.storeBit(false);
      }
      cb.storeBit(false); // body inlined
      cb.storeBytes(signature); // signature
    }
    cb.storeInt (0, 32); //subwallet
    cb.storeInt (valid_until, 32); //unix_time
    cb.storeInt (seqno, 32); //seqno
    cb.storeInt (3, 8); // send mode
    
    CellBuilder cb2 = CellBuilder.beginCell ();
    // 0 - internal message
    // 1 - ihr disabled
    boolean []b1 = {false, true};
    cb2.storeBits (b1);
    cb2.storeBit (dst.isBounceable);
    // 0 - bounced
    // 00 - src address is omitted
    // 10 - msg addr std
    // 0 - not anycast
    boolean []b2 = {false, false, false, true, false, false};
    cb2.storeBits (b2);
    cb2.storeInt (dst.wc, 8);
    cb2.storeBytes (dst.hashPart);
    cb2.storeCoins (BigInteger.valueOf(grams));

    // magic:
    //   0 - empty extra currency collection 
    //   ihr_fee = 0G, 4 bit
    //   fwd_fee = 0G, 4 bit
    //   created_lt = 0LL, 64 bits
    //   created_at = 0I, 32 bits
    //   state = false, 1 bit
    cb2.storeUint(0, 1 + 4 + 4 + 64 + 32 + 1);
    if (payload_cell.bits.getUsedBits() > 0) {
      cb2.storeBit(true); // message body in a reference
      cb2.storeSlice (CellSlice.beginParse(payload_cell));
    } else {
      cb2.storeBit(false); // inlined message body
      if (payload.length() > 0) {
        cb2.storeInt (0, 32);
        cb2.storeString (payload);
      }
    }
    cb.storeRef (cb2.endCell ());
    return cb.endCell ();
  }
  private static Cell create_unsigned_message(int seqno, int valid_until, String payload, Cell payload_cell, byte key[], Address src, Address dst, long grams) {
    byte [] signature = {};
    return create_message (signature, seqno, valid_until, payload, payload_cell, key, src, dst, grams); 
  }
  public static byte[] create_data_to_sign(int seqno, int valid_until, String payload, Cell payload_cell, byte key[], Address src, Address dst, long grams) {
    return create_unsigned_message (seqno, valid_until, payload, payload_cell, key, src, dst, grams).hash (); 
  }
  public static byte[] create_signed_message(byte [] signature, int seqno, int valid_until, String payload, Cell payload_cell, byte key[], Address src, Address dst, long grams) {
    return create_message (signature, seqno, valid_until, payload, payload_cell, key, src, dst, grams).toBoc (); 
  }
  public static byte[] create_in_msg_hash (byte [] signature, int seqno, int valid_until, String payload, Cell payload_cell, byte key[], Address src, Address dst, long grams) {
    return create_message (signature, seqno, valid_until, payload, payload_cell, key, src, dst, grams).toBoc (); 
  }

  public static String uniform_account_name (byte workchain, ShortTxId tx) {
    if (tx == null || tx.getAccount () == null) {
      return "NULL";
    }
    var addr = new Address (workchain + ":" + Utils.base64ToHexString(tx.getAccount()));
    return addr.toString (true, false, true, false);
  }

  public static String uniform_account_name (byte workchain, AccountAddressOnly a) {
    if (a == null || a.getAccount_address () == null || a.getAccount_address ().equals ("")) {
      return "NULL";
    }
    var addr = new Address (a.getAccount_address ());
    return addr.toString (true, false, true, false);
  }
  public boolean skip_account_in_transaction_list (String account) {
    return false;
  }

  public static BigInteger readGrams (BitString bs) {
    var x = bs.readUint (4);
    if (x.intValue () > 0) {
      return bs.readUint (8 * x.intValue ());
    } else {
      return BigInteger.ZERO;
    }
  }
  
  public static BigInteger readGramsCheck (BitString bitstring, BigInteger value) {
    BigInteger r = readGrams (bitstring);
    assert (r == value);
    return r;
  }
  
  public static BigInteger readGramsCheck (BitString bitstring, String value) {
    return readGramsCheck (bitstring, new BigInteger (value));
  }

  public void new_transaction_callback (byte workchain, RawTransaction rt) {
    //if (skip_account_in_transaction_list (uniform_account_name (workchain, tx))) {
    //  return;
    //}
    //System.out.println ("new transaction " + tx.toString ());
    //var rt = tonlib.getRawTransaction(workchain, tx); 
    //System.out.println ("raw new transaction " + rt.toString ());

    var in_msg = rt.getIn_msg ();

    // TIC-TOC, only in system accounts
    if (in_msg == null || in_msg.getSource () == null) {
      return;
    }

    var out_msgs = rt.getOut_msgs();

    var data_string = Utils.base64ToBytes (rt.getData ());
    var data_cell = Cell.fromBoc (data_string); 

    {
      assert (data_cell.bits.readBit () == false);
      assert (data_cell.bits.readBit () == true);
      assert (data_cell.bits.readBit () == true);
      assert (data_cell.bits.readBit () == true);
    }

    var descr = data_cell.refs.get (2);

    boolean reg = true;
    for (int i = 0; i < 4; i++) {
      if (descr.bits.readBit () != false) {
        reg = false;
        break;
      }
    }

    boolean failed = false;
    boolean action_failed = false;
    if (!reg) {
      System.out.println ("NOT REGULAR TRANSACTION");
    } else {
      int ref_skipped = 0;
      descr.bits.readBit (); // credit first (?)
      boolean has_storage_phase = descr.bits.readBit ();
      if (has_storage_phase) {
        /* coins */
        readGramsCheck (descr.bits, rt.getStorage_fee ());
        boolean has_due = descr.bits.readBit ();
        if (has_due) {
          readGrams (descr.bits); // due
        }
        var changed_status = descr.bits.readBit ();
        if (changed_status) {
          descr.bits.readBit ();  
        }
      }
      boolean has_credit_phase = descr.bits.readBit ();
      if (has_credit_phase) {
        boolean has_due_collected = descr.bits.readBit ();
        if (has_due_collected) {
          readGrams (descr.bits); // due collected
        }
          
        readGrams (descr.bits); // value to credit
        boolean has_hashmap = descr.bits.readBit (); // extra currencies 
        if (has_hashmap) {
          ref_skipped += 1;
        }
      }
      boolean has_compute_phase = true;
      if (has_compute_phase) {
        boolean runned = descr.bits.readBit ();
        if (!runned) {
          failed = true;
          descr.bits.readBits (2); // reason
        } else {
          boolean success = descr.bits.readBit ();
          has_storage_phase &= success;
          descr.bits.readBits (2); // msg_state_used + account_activated
          readGrams (descr.bits); // gas_fees
          ref_skipped += 1; // vm run info
          // there is an exit code, among other stuff, maybe parse?
        }
      }
      boolean has_action_phase = descr.bits.readBit ();
      if (has_action_phase) {
        Cell act_cell = descr.refs.get (ref_skipped);
        ref_skipped += 1;
        boolean success = act_cell.bits.readBit ();
        if (!success) {
          action_failed = true;
        }
        // maybe parse more here?
      }
      boolean aborted = descr.bits.readBit ();
      if (aborted) {
        failed = true;
      }

      // bounce and destroyed not parsed, at least for now
    }

    /* inbound message, probably inbound transfer */
    if (out_msgs.size() == 0) {
      System.out.println ("Inbound transfer: from=" + uniform_account_name (workchain, in_msg.getSource ()) 
                          + " to=" + uniform_account_name (workchain, in_msg.getDestination ()) + " value=" 
                          + in_msg.getValue ()  +" fwd_fee=" + in_msg.getFwd_fee () + " fee=" + rt.getFee () 
                          + " storage_fee=" + rt.getStorage_fee () + " failed=" + failed + " action_failed=" + action_failed); 
    } else {
      for (var out_msg : out_msgs) {
        System.out.println ("Outbound transfer: from=" + uniform_account_name (workchain, out_msg.getSource ()) 
                            + " to=" + uniform_account_name (workchain, out_msg.getDestination ()) + " value=" 
                            + out_msg.getValue () + " fwd_fee=" + out_msg.getFwd_fee () + " fee(total)=" + rt.getFee () 
                            + " storage_fee(total)=" + rt.getStorage_fee () + " failed=" + failed + " action_failed=" + action_failed);
      }
    }
  
    var info = jetton_message_get_info (in_msg);
    if (info.value != BigInteger.valueOf(0) && info.src_wallet != null && info.dst_wallet != null) {
      System.out.println ("value = " + info.value + " workchain = " + workchain + " src = " + info.src_wallet.toString(true, false, true, false) + 
          " dst = " + info.dst_wallet.toString(true, false, true, false));
      var req = JsonStream.serialize(rt);
      System.out.println ("json = " + req);
    }
  }
  
  public void scan_new_block_transactions (BlockIdExt block_id) {
    System.out.println ("scanning block with seqno " + last_mc_seqno);
    BlockTransactionsExt t = tonlib.getBlockTransactionsExt(block_id, 10);

    while (true) {
      List<RawTransaction> transactions = t.getTransactions ();
      for (var tx : transactions) {
        new_transaction_callback ((byte)block_id.getWorkchain().intValue (), tx);
      }
      
      if (!t.isIncomplete () || transactions.size() == 0) {
        break;
      }
 
      var last = transactions.get(transactions.size() - 1);
      var last_id = last.getTransaction_id();
      var last_addr = new Address(last.getAddress().getAccount_address());

      System.out.println ("seqno=" + block_id.getSeqno() + " last_addr=" + last_addr.toString ());
      t = tonlib.getBlockTransactionsExt (block_id, 1, last_id.getLt().longValue (), Utils.bytesToBase64(last_addr.hashPart));
    }
  }

  public void scan_new_block_transactions_rec (BlockIdExt block_id, int depth) {
    if (last_shards.contains (block_id.toString ())) {
      return;
    }
    if (depth >= 16) {
      // ASSERT?
      return;
    }
    BlockHeader head = tonlib.getBlockHeader (block_id);
    if (head.isAfter_split() || head.isAfter_merge()) {
      scan_new_block_transactions (block_id);
      return;
    }

    var prev_blocks = head.getPrev_blocks ();
    // assert? it is not split/merge
    if (prev_blocks.size() != 1) {
      scan_new_block_transactions (block_id);
      return;
    }

    BlockIdExt prev_block = prev_blocks.get (0);

    scan_new_block_transactions_rec (prev_block, depth + 1);
    scan_new_block_transactions (block_id);
  }

  public void scan_new_mc_block_transactions (long seqno) {
    System.out.println ("scanning mc block with seqno " + last_mc_seqno);
    BlockIdExt block_id = tonlib.lookupBlock(seqno, -1, 0x8000000000000000L, 0, 0);
    if (block_id.getSeqno ().longValue () < seqno) {
      return;
    }

    scan_new_block_transactions (block_id);
  
    HashSet<String> new_last_shards = new HashSet<String> ();

    var shardsR = tonlib.getShards(block_id);
    var shards = shardsR.getShards ();
    for (BlockIdExt shard : shards) {
      new_last_shards.add (shard.toString ());
      scan_new_block_transactions_rec (shard, 0);
    }

    last_mc_seqno = block_id.getSeqno ().longValue ();
    last_shards = new_last_shards;
  }

  public boolean scan_new_transactions () {
    MasterChainInfo mi = tonlib.getLast (); 
    long new_seqno = mi.getLast().getSeqno().longValue ();
    if (new_seqno == last_mc_seqno) {
      return false;
    }
    while (last_mc_seqno < new_seqno) {
      scan_new_mc_block_transactions (last_mc_seqno + 1);
    }

    return true;
  }

  public void loop() {
    boolean quit = false;
    while (!quit) {
      try {
        System.out.println ("scanning block with seqno " + last_mc_seqno);
        scan_new_transactions ();
      } catch (Exception e) {
        System.out.println ("exception");
        throw e;
        // try again later?
        // check exception type?
      }
      try {
        TimeUnit.SECONDS.sleep(1);
      } catch (java.lang.InterruptedException e) {
        quit = true;
      }
    }
    System.out.println ("result mc seqno " + last_mc_seqno);
  }

  public void run () throws Exception {
    Tonlib tl = new Tonlib ();
    tl.setPathToGlobalConfig ("./config.json");
    tl.setPathToTonlibSharedLib ("./libtonlibjson.so");
    tl.setKeystoreInMemory (true);
    tl.setVerbosityLevel (VerbosityLevel.FATAL);
    tl.initTonlib();
    var tonIO = tl.getTonIO();;
    tonlib = tonIO.getTonClient ();
    BlockIdExt last_mc_block = tonlib.getLast().getLast();
    System.out.println ("last block_seqno is " + last_mc_block.getSeqno().longValue ()); 
    last_mc_block = tonlib.getLast().getLast();
    System.out.println ("last block_seqno is " + last_mc_block.getSeqno().longValue ()); 
    last_mc_seqno = last_mc_block.getSeqno ().longValue ();
    last_shards = new HashSet<String> ();
    known_contracts = new HashMap<String,String> ();
    known_contracts.put ("a7a2616a4d639a076c2f67e7cce0423fd2a1c2ee550ad651c1eda16ee13bcaca", "nft_item");
    known_contracts.put ("4c9123828682fa6f43797ab41732bca890cae01766e0674100250516e0bf8d42", "nft_item");
    known_contracts.put ("9892766765d3ea42809a417abbd7ff9ce681b145d05ae6b118a614b38c8ded15", "nft_item_editable");
    known_contracts.put ("959fc9a86b4b2436a1256ee1c02a58481a58488df91ecdd6c186d580b00be40a", "nft_single");
    known_contracts.put ("64bb2d4661b5f2dc1a83bf5cbbe09e92ac0b460a1b879a5519386fca4c348bca", "nft_collection_editable");
    known_contracts.put ("88410c220f822181668269ce83eb9cc0d3b39c21999c8b55de03360a20e7c282", "nft_collection_no_dns");
    known_contracts.put ("9a0f98dd6fbf225eef8165e4e64417ee931f7eea000653439e7b5dcdc0644cd6", "jetton");
    known_contracts.put ("beb0683ebeb8927fe9fc8ec0a18bc7dd17899689825a121eab46c5a3a860d0ce", "jetton_wallet");
    known_contracts.put ("feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0", "wallet_v4_r2");
    known_contracts.put ("84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599", "wallet_v3_r2");
    known_contracts.put ("89468f02c78e570802e39979c8516fc38df07ea76a48357e0536f2ba7b3ee37b", "jetton_smartcontract");
    var shardsR = tonlib.getShards(last_mc_block);
    var shards = shardsR.getShards ();
    for (BlockIdExt shard : shards) {
      last_shards.add (shard.toString ());  
    }
  }

  public long get_seqno (Address addr) {
    AccountAddressOnly accountAddressOnly = AccountAddressOnly.builder()
            .account_address(addr.toString(false))
            .build();
    var account_state = tonlib.getRawAccountState(accountAddressOnly);
    if (account_state == null) {
      return 0;
    }
    var account_data = account_state.getData ();
    if (account_data == null || account_data.equals ("")) {
      return 0;
    }
    var cell = Cell.fromBoc (Utils.base64ToBytes (account_data));
    return cell.bits.preReadUint (32).intValue ();
  }

  public String get_account_type (Address addr) {
    AccountAddressOnly accountAddressOnly = AccountAddressOnly.builder()
            .account_address(addr.toString(false))
            .build();
    var account_state = tonlib.getRawAccountState(accountAddressOnly);
    if (account_state == null) {
      return "not_inited";
    }
    var account_code = account_state.getCode ();
    if (account_code == null || account_code.equals ("")) {
      return "not_inited";
    }
    
    var cell = Cell.fromBoc (Utils.base64ToBytes (account_code));
    var h = Utils.bytesToHex (cell.hash ());

    if (known_contracts.containsKey (h)) {
      return known_contracts.get (h); 
    } else {
      return "#" + h;
    }
  }
  
  private Address dns_resolve_in (String name, AccountAddressOnly acc_only) {
    var result = tonlib.dnsResolve (name, acc_only);
    if (result == null) {
      return null;
    }
    var entries = result.getEntries ();
    if (entries == null) {
      return null;
    }
    for (var entry : entries) {
      var info = entry.getEntry ();
      if (info == null) {
        continue;
      }
      if (info.getType ().equals ("dns.entryDataNextResolver")) {
        /* can return Address (info.getResolver ()), if only *.ton and *.t.me are supported */
        return dns_resolve_in (entry.getName (), info.getResolver ());
      } else {
        return new Address (acc_only.getAccount_address ());
      }
    }
    return new Address (acc_only.getAccount_address ());
  }

  public Address dns_resolve (String name) {
    return dns_resolve_in (name, null);
  }

  public Address dns_get_owner (Address addr) {
    AccountAddressOnly accountAddressOnly = AccountAddressOnly.builder()
            .account_address(addr.toString(false))
            .build();
    var account_state = tonlib.getRawAccountState(accountAddressOnly);
    if (account_state == null) {
      return null;
    }
    var account_data = account_state.getData ();
    if (account_data == null) {
      return null;
    }
    var cell = Cell.fromBoc (Utils.base64ToBytes (account_data));
    cell = cell.refs.get (1);
    var b = cell.bits;
    b.readBits (3);
    var workchain = b.readInt (8).intValue ();
    var data = b.readBytes (32 * 8);
    return new Address ("" + workchain + ":" + Utils.bytesToHex (data));
  }

  static String fetch_serialized_link (Cell cell) {
    var bits = cell.bits;
    var firstChar = bits.preReadUint (8);
    if (firstChar.longValue () == 1 /* offchain tag */) {
      bits.readBits (8);
      return bits.readString (bits.writeCursor - bits.readCursor); 
    } 
    /* TODO: parse onchain tag */
    return "";
  }

  static String fetch_string (Cell cell) {
    var bits = cell.bits;
    return bits.readString (bits.writeCursor - bits.readCursor); 
  }

  /* nft_single */
  public String nft_single_get_content (Address addr) {
    AccountAddressOnly accountAddressOnly = AccountAddressOnly.builder()
            .account_address(addr.toString(false))
            .build();
    var account_state = tonlib.getRawAccountState(accountAddressOnly);
    if (account_state == null) {
      return "";
    }
    var account_data = account_state.getData ();
    if (account_data == null || account_data.equals ("")) {
      return "";
    }
   
    var cell = Cell.fromBoc (Utils.base64ToBytes (account_data));
    if (cell.refs.size () < 1) {
      return "";
    }

    return fetch_serialized_link (cell.refs.get (0));
  }
  
  /* nft_collection + nft_collection_editable */
  public String[] nft_collection_get_content (Address addr) {
    AccountAddressOnly accountAddressOnly = AccountAddressOnly.builder()
            .account_address(addr.toString(false))
            .build();
    var account_state = tonlib.getRawAccountState(accountAddressOnly);
    if (account_state == null) {
      return new String[]{};
    }
    var account_data = account_state.getData ();
    if (account_data == null || account_data.equals ("")) {
      return new String[]{};
    }
   
    var cell = Cell.fromBoc (Utils.base64ToBytes (account_data));
    if (cell.refs.size () < 1) {
      return new String[]{};
    }

    cell = cell.refs.get (0);
    if (cell.refs.size () < 2) {
      return new String[]{};
    }
    
    String collectionInfo = fetch_serialized_link (cell.refs.get (0));
    String collectionItemPrefix = fetch_string (cell.refs.get (1));
      
    return new String[]{collectionInfo, collectionItemPrefix};
  }
 
  /* nft_item + nft_item_editable */
  public String nft_item_get_content (Address addr) {
    AccountAddressOnly accountAddressOnly = AccountAddressOnly.builder()
            .account_address(addr.toString(false))
            .build();
    var account_state = tonlib.getRawAccountState(accountAddressOnly);
    if (account_state == null) {
      return "";
    }
    var account_data = account_state.getData ();
    if (account_data == null || account_data.equals ("")) {
      return "";
    }

    var cell = Cell.fromBoc (Utils.base64ToBytes (account_data));
    var bits = cell.bits;
    bits.readInt (64); // index
    
    bits.readBits (3);
    var workchain = bits.readInt (8).intValue ();
    var data = bits.readBytes (32 * 8);

    var owner = new Address ("" + workchain + ":" + Utils.bytesToHex (data));
    var t = nft_collection_get_content (owner);
    
    if (t.length == 0) {
      return "";
    }
    assert (t.length == 2);
    
    if (cell.refs.size () < 1) {
      return "";
    }

    var info = fetch_string (cell.refs.get (0));
    if (info.equals ("")) {
      return "";
    }
    return t[1] + info;
  }

  public void stop() {
  }

  public static byte[] read_whole_file (String name) throws Exception {
    try {
      FileInputStream fileIS = new FileInputStream(name);
      return fileIS.readAllBytes();
    } catch (Exception e) {
      throw e;
    }
  }
  
  public static byte[] read_public_key (String fname) throws Exception {
    byte[] arr = read_whole_file (fname);
    if (arr.length != 36) {
      System.out.println ("pubkey bad size");
      throw new Exception ("AAA");
    }
    if (arr[0] != (byte)0xc6) {
      System.out.println ("pubkey bad magic");
      throw new Exception ("AAA");
    }
    byte[] pubkey = Arrays.copyOfRange(arr, 4, 36);
    if (pubkey.length != 32) {
      System.out.println ("pubkey bad size");
      throw new Exception ("AAA");
    }
    return pubkey;
  }
  
  public static Address amton_master_address() throws Exception {
    Cell masterScCode = Cell.fromBoc (read_whole_file ("master_code.boc")); 
    Cell walletScCode = Cell.fromBoc (read_whole_file ("wallet_code.boc")); 

    Address owner = new Address ("0QDPk_hRKx4BZaxBIixSYiIzNwAn9CfhP0uZuMqD5OaKjKTc");

    CellBuilder contentB = CellBuilder.beginCell();
    Cell content = contentB.endCell();

    CellBuilder masterScDataB = CellBuilder.beginCell(); 
    masterScDataB.storeInt (0, 1); // inited
    masterScDataB.storeCoins(/*total supply*/BigInteger.valueOf(0));
    masterScDataB.storeCoins(/*nanograms per coin*/BigInteger.valueOf(1000000000));
    masterScDataB.storeBits (new boolean[]{true, false, false});
    masterScDataB.storeInt (owner.wc, 8);
    masterScDataB.storeBytes (owner.hashPart);
    masterScDataB.storeRef (content);
    masterScDataB.storeRef (walletScCode);
    Cell masterScData = masterScDataB.endCell();

    CellBuilder init_code = CellBuilder.beginCell();
    init_code.storeBits (new boolean[]{false, false, true, true}); // magic
    init_code.storeRef (masterScCode);
    init_code.storeRef (masterScData);
    init_code.storeBit (false); // empty HashMap = Libraries
                                                 
    byte []init_code_hash = init_code.endCell().hash();

    return new Address("0:" + Utils.bytesToHex(init_code_hash));
  };
  
  public static Address amton_wallet_address(byte[] pubkey) throws Exception {
    Address master_address = amton_master_address();
    Cell walletScCode = Cell.fromBoc (read_whole_file ("wallet_code.boc")); 

    CellBuilder walletScDataB = CellBuilder.beginCell(); 
    walletScDataB.storeCoins(/*balance*/BigInteger.valueOf(0));
    walletScDataB.storeBytes(/*pubkey*/pubkey);
    walletScDataB.storeInt(/*seqno*/0, 32);
    walletScDataB.storeInt(/*sent_request*/0, 1);
    walletScDataB.storeBits(new boolean[]{true, false, false}); // 10 - AddrStd + 0 - Anycast
    walletScDataB.storeInt(master_address.wc, 8);
    walletScDataB.storeBytes(master_address.hashPart);
    
    Cell walletScData = walletScDataB.endCell();

    CellBuilder init_code = CellBuilder.beginCell();
    init_code.storeBits (new boolean[]{false, false, true, true}); // magic
    init_code.storeRef (walletScCode);
    init_code.storeRef (walletScData);
    init_code.storeBit (false); // empty HashMap = Libraries
                                                 
    byte []init_code_hash = init_code.endCell().hash();

    return new Address("0:" + Utils.bytesToHex(init_code_hash));
  };

  public static Cell amton_init_smartcontract() throws Exception {
    Cell masterScCode = Cell.fromBoc (read_whole_file ("master_code.boc")); 
    Cell walletScCode = Cell.fromBoc (read_whole_file ("wallet_code.boc")); 

    Address owner = new Address ("0QDPk_hRKx4BZaxBIixSYiIzNwAn9CfhP0uZuMqD5OaKjKTc");

    CellBuilder contentB = CellBuilder.beginCell();
    Cell content = contentB.endCell();

    CellBuilder masterScDataB = CellBuilder.beginCell(); 
    masterScDataB.storeInt (0, 1); // inited
    masterScDataB.storeCoins(/*total supply*/BigInteger.valueOf(0));
    masterScDataB.storeCoins(/*nanograms per coin*/BigInteger.valueOf(1000000000));
    masterScDataB.storeBits (new boolean[]{true, false, false});
    masterScDataB.storeInt (owner.wc, 8);
    masterScDataB.storeBytes (owner.hashPart);
    masterScDataB.storeRef (content);
    masterScDataB.storeRef (walletScCode);
    Cell masterScData = masterScDataB.endCell();

    CellBuilder init_code = CellBuilder.beginCell();
    init_code.storeBits (new boolean[]{false, false, true, true}); // magic
    init_code.storeRef (masterScCode);
    init_code.storeRef (masterScData);
    init_code.storeBit (false); // empty HashMap = Libraries
                                                 
    byte []init_code_hash = init_code.endCell().hash();

    Address masterScAddress = new Address("0:" + Utils.bytesToHex(init_code_hash));
    System.out.println ("ADDRESS = " + masterScAddress);


    CellBuilder cb = CellBuilder.beginCell ();
    boolean []b01 = {true, false, false, false, true, false, false};
    cb.storeBits(b01);
    cb.storeInt (masterScAddress.wc, 8);
    cb.storeBytes (masterScAddress.hashPart);
    cb.storeCoins (BigInteger.valueOf(0)); // import fee
    cb.storeBit(true); // has_state
    cb.storeBit(false); // state is inlined
    cb.storeBit(false); // splitdepth
    cb.storeBit(false); // special
    cb.storeBit(true); // code
    cb.storeBit(true); // data
    cb.storeBit(false); // libraries

    cb.storeRef (masterScCode);
    cb.storeRef (masterScData);
    
    cb.storeBit(false); // body inlined
    
    return cb.endCell ();
  }
  
  public static Cell mint_boc(String fname) throws Exception {
    byte[] arr = read_whole_file (fname);
    if (arr.length != 36) {
      System.out.println ("pubkey bad size");
      throw new Exception ("AAA");
    }
    if (arr[0] != (byte)0xc6) {
      System.out.println ("pubkey bad magic");
      throw new Exception ("AAA");
    }
    byte[] pubkey = Arrays.copyOfRange(arr, 4, 36);
    if (pubkey.length != 32) {
      System.out.println ("pubkey bad size");
      throw new Exception ("AAA");
    }

    CellBuilder cb = CellBuilder.beginCell ();
    cb.storeInt (0xddc9b4d4, 32);
    cb.storeInt (0, 64);
    cb.storeCoins (BigInteger.valueOf (10000000000L));
    cb.storeBytes (pubkey);

    return cb.endCell ();
  }

  private static Cell amton_create_transfer_boc (byte[] src_public_key, byte[] dst_public_key, int valid_until, int seqno, long amount) throws Exception {
    Address src = amton_wallet_address (src_public_key);
    byte[] signature = new byte[64];
    for (int i = 0; i < 32; i++) {
      signature[i] = src_public_key[i];
    }

    CellBuilder cb2 = CellBuilder.beginCell ();
    cb2.storeBytes(signature); // signature
    
    cb2.storeInt (valid_until, 32); //unix_time
    cb2.storeInt (seqno, 32); //seqno
    cb2.storeInt (0xf8a7ea5, 32);
    cb2.storeInt (0, 64); // query_id
    cb2.storeCoins (BigInteger.valueOf (amount));
    cb2.storeBytes (dst_public_key);


    CellBuilder cb = CellBuilder.beginCell ();
    // 10 - external message
    // 00 - src addr none 
    // 10 - addr-std
    // 0 - not anycast
    boolean []b01 = {true, false, false, false, true, false, false};
    cb.storeBits(b01);
    cb.storeInt (src.wc, 8);
    cb.storeBytes (src.hashPart);
    cb.storeCoins (BigInteger.valueOf(0)); // import fee
    cb.storeBit(false);
    cb.storeBit(true); // body NOT inlined
    cb.storeRef(cb2.endCell());

    return cb.endCell ();
  }
  
  private static Cell create_withdraw_message (long amount) throws Exception {
    CellBuilder cb = CellBuilder.beginCell ();
    cb.storeInt (0x1000, 32);
    cb.storeInt (0, 64); // query_id
    cb.storeCoins (BigInteger.valueOf(amount)); 

    return cb.endCell ();
  }


  private static Cell jetton_wallet_code() throws Exception {
    CellBuilder cb = CellBuilder.beginCell ();
    cb.storeBytes (Utils.hexToBytes("028F452D7A4DFD74066B682365177259ED05734435BE76B5FD4BD5D8AF2B7C3D68"));
    Cell res = cb.endCell();
    res.isExotic = true;
    return res;
  }
  
  private static Cell jetton_wallet_init_data(Address owner_address, Address jetton_master_address) throws Exception {
    CellBuilder cb = CellBuilder.beginCell ();
    cb.storeUint(0, 4); // STATUS
    cb.storeCoins(BigInteger.valueOf(0)); // BALANCE

    // owner address
    cb.storeBits(new boolean[]{true, false, false});
    cb.storeInt(owner_address.wc, 8);
    cb.storeBytes(owner_address.hashPart);
    
    // response address
    cb.storeBits(new boolean[]{true, false, false});
    cb.storeInt(jetton_master_address.wc, 8);
    cb.storeBytes(jetton_master_address.hashPart);

    return cb.endCell();
  }

  private static Cell jetton_wallet_state_init(Address owner_address, Address jetton_master_address) throws Exception {
    CellBuilder cb = CellBuilder.beginCell ();
    cb.storeUint(0, 2); // no split depth, no special
    cb.storeBit(true); // has code
    cb.storeRef(jetton_wallet_code());
    cb.storeBit(true); // has data
    cb.storeRef(jetton_wallet_init_data(owner_address, jetton_master_address));
    cb.storeBit(false); // has no libraries
    return cb.endCell();
  }


  private static Address jetton_wallet_calculate_address(Address owner_address, Address jetton_master_address) throws Exception {
    Cell state_init = jetton_wallet_state_init (owner_address, jetton_master_address);
    return new Address("0:" + Utils.bytesToHex(state_init.hash()));
  }


  private long jetton_wallet_get_balance(Address addr) throws Exception {
    AccountAddressOnly accountAddressOnly = AccountAddressOnly.builder()
            .account_address(addr.toString(false))
            .build();
    var account_state = tonlib.getRawAccountState(accountAddressOnly);
    if (account_state == null) {
      return 0;
    }
    var account_code = account_state.getCode ();
    if (account_code == null || account_code.equals ("")) {
      return 0;
    }
    
    var account_data = account_state.getData ();
    if (account_data == null || account_data.equals ("")) {
      return 0;
    }
    var cell = Cell.fromBoc (Utils.base64ToBytes (account_data));
    var parser = CellSlice.beginParse(cell);
    BigInteger state = parser.loadUint(4);
    BigInteger balance = parser.loadCoins();
    Address owner = parser.loadAddress();
    Address master = parser.loadAddress();

    System.out.println ("wallet " + addr.toString (true, false, true, false) + " owner=" 
        + owner.toString(true, false, true, false) + " master=" + master.toString(true, false, true, false)
        + " balance=" + balance.toString() + " state=" + state.toString());

    return balance.longValue();
  }
 
  private BigInteger jetton_message_get_transfer_amount(RawMessage message) {
    try {
      var body = message.getMsg_data().getBody();
      var body_cell = Cell.fromBoc (Utils.base64ToBytes (body)); 
      var slice = CellSlice.beginParse(body_cell);
        
      long op = slice.loadUint(32).longValue();

      long transfer_opcode = 0xf8a7ea5L; 
      long inbound_transfer_opcode = Long.valueOf("178d4519", 16);
      long burn_opcode = Long.valueOf("595f07bc", 16);

      if (op != transfer_opcode && op != inbound_transfer_opcode && op != burn_opcode) {
        return BigInteger.valueOf(0);
      }

      BigInteger query_id = slice.loadUint(64);
      BigInteger value = slice.loadCoins();

      if (op == inbound_transfer_opcode) {
        return value;
      } else {
        return value.multiply(new BigInteger("-1"));
      }
    } catch (Exception e) {
      return BigInteger.valueOf(0);
    } catch (Error e) {
      return BigInteger.valueOf(0);
    }
    //return BigInteger.zero();
  }
 
  class JettonMessageInfo {
    JettonMessageInfo(BigInteger _value, Address _src_wallet, Address _dst_wallet) {
      value = _value;
      src_wallet = _src_wallet;
      dst_wallet = _dst_wallet;
    }
    public BigInteger value;
    public Address src_wallet;
    public Address dst_wallet;
  };

  private JettonMessageInfo jetton_message_get_info(RawMessage message) {
    try {
      var body = message.getMsg_data().getBody();
      var body_cell = Cell.fromBoc (Utils.base64ToBytes (body)); 
      var slice = CellSlice.beginParse(body_cell);
        
      long op = slice.loadUint(32).longValue();

      long transfer_opcode = 0xf8a7ea5L; 
      long inbound_transfer_opcode = Long.valueOf("178d4519", 16);
      long burn_opcode = Long.valueOf("595f07bc", 16);

      if (op != transfer_opcode && op != inbound_transfer_opcode && op != burn_opcode) {
        return new JettonMessageInfo(BigInteger.valueOf(0), null, null);
      }

      BigInteger query_id = slice.loadUint(64);
      BigInteger value = slice.loadCoins();
      Address src_wallet = slice.loadAddress();
      Address dst_wallet = slice.loadAddress();

      if (op == inbound_transfer_opcode) {
        return new JettonMessageInfo(value, src_wallet, dst_wallet);
      } else {
        return new JettonMessageInfo(value.multiply(new BigInteger("-1")), src_wallet, dst_wallet);
      }
    } catch (Exception e) {
      return new JettonMessageInfo(BigInteger.valueOf(0), null, null);
    } catch (Error e) {
      return new JettonMessageInfo(BigInteger.valueOf(0), null, null);
    }
    //return BigInteger.zero();
  }

  private static Cell jetton_create_transfer_boc (Address src, Address dst, Address master_address, long jetton_amount, String comment) throws Exception {
    Address jetton_src = jetton_wallet_calculate_address (src, master_address);
    Address jetton_dst = jetton_wallet_calculate_address (dst, master_address);

    CellBuilder cb = CellBuilder.beginCell ();
    cb.storeInt(System.nanoTime(), 64); // query_id, maybe use random? 
    cb.storeCoins(BigInteger.valueOf(jetton_amount));
   
    // dst address
    cb.storeBits(new boolean[]{true, false, false});
    cb.storeInt(jetton_dst.wc, 8);
    cb.storeBytes(jetton_dst.hashPart);
    
    // response address
    cb.storeBits(new boolean[]{true, false, false});
    cb.storeInt(src.wc, 8);
    cb.storeBytes(src.hashPart);
  
    cb.storeBit(false); // custom payload

    cb.storeCoins(BigInteger.valueOf(0)); // forward ton amount
    
    if (comment.length() > 0) {
      cb.storeInt (0, 32);
      cb.storeString(comment);
    }

    return cb.endCell();
  }

  public static void main (String args[]) throws Exception {
    JsoniterSpi.registerTypeEncoder(UUID.class,new UUIDCodec());
    //Register decoders.
    JsoniterSpi.registerTypeDecoder(UUID.class,new UUIDCodec());
    //Register key map encoders.
    JsoniterSpi.registerMapKeyEncoder(UUID.class,new UUIDCodec());
    JsoniterSpi.registerMapKeyDecoder(UUID.class,new UUIDCodec());

    /*if (args[0].equals ("minter_addr")) {
      Address res = Exec.amton_master_address();
      System.out.println ("masterAddr = " + res.toString (true, false, true, false));
    } else if (args[0].equals ("minter")) {
      Cell res = Exec.amton_init_smartcontract();
      res.toFile ("init_external_message.boc", true);
    } else if (args[0].equals ("mint_boc")) {
      Cell res = Exec.mint_boc(args[1]);
      res.toFile (args[1] + ".mint.boc", true);
    } else if (args[0].equals ("wallet_addr")) {
      Address res = Exec.amton_wallet_address(Exec.read_public_key(args[1]));
      System.out.println ("walletaddr = " + res.toString (true, false, true, false));
    } else if (args[0].equals ("withdraw")) {
      long amount = Long.valueOf(args[1]); 
      Cell res = Exec.create_withdraw_message (amount);
      res.toFile ("withdraw.boc", true);
    } else if (args[0].equals ("transfer")) {
      byte[] srcPubKey = Exec.read_public_key(args[1]);
      byte[] dstPubKey = Exec.read_public_key(args[2]);
      int valid_until = Integer.valueOf(args[3]);
      int seqno = Integer.valueOf(args[4]);
      long amount = Long.valueOf(args[5]); 

      Cell res = Exec.amton_create_transfer_boc (srcPubKey, dstPubKey, valid_until, seqno, amount);
      res.toFile ("query.boc", true);
    }*/

    /*{
      Address usdt_to_master_address = new Address ("EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs");
      Address wallet_address = new Address ("UQDAqpBz_rORIhoKXEcHJG0Jyj6G8H3rGLg5MGeXgkh8b5b4");
      Address addr = jetton_wallet_calculate_address (wallet_address, usdt_to_master_address);
      System.out.println ("tonusdt address = " + addr.toString(true, false, true, false));
      System.exit(-1);
    }*/

    Exec exc = new Exec ();

    exc.run ();
    exc.loop ();
    System.out.println (exc.get_account_type (new Address ("EQCcKgiMgfJi4eAnKwhN9yJFlINzllXo0oeuFTEe4rXThOJX")));
    exc.jetton_wallet_get_balance(new Address ("EQCcKgiMgfJi4eAnKwhN9yJFlINzllXo0oeuFTEe4rXThOJX"));
    //System.out.println (exc.nft_item_get_content (new Address ("EQCRH0vtTG-7rgWRfsNaVJIzDLY9d0J51z-bQOfbaJt2zWOm")));

    System.out.println (exc.get_account_type (new Address ("EQD4g62_gEY7s2xHf3Fs-Yl6oar1YSwBInWdChUQPkMb91hu")));
    System.out.println (exc.get_account_type (new Address ("EQCRH0vtTG-7rgWRfsNaVJIzDLY9d0J51z-bQOfbaJt2zWOm")));
    System.out.println (exc.get_account_type (new Address ("EQB8D8A9OoDoRmL7qVbUBrd_po9vNKcl44HCSw6b-c3nvcj9")));
    System.out.println (exc.get_account_type (new Address ("EQDye65-jeR8kz8MlfnS0qX-5HPF_Zq4pZSKrLFSedJumy89")));
    System.out.println (exc.get_account_type (new Address ("EQAOQdwdw8kGftJCSFgOErM1mBjYPe4DBPq8-AhF6vr9si5N")));

    System.out.println (exc.nft_single_get_content (new Address ("EQD4g62_gEY7s2xHf3Fs-Yl6oar1YSwBInWdChUQPkMb91hu")));
    System.out.println (exc.nft_item_get_content (new Address ("EQCRH0vtTG-7rgWRfsNaVJIzDLY9d0J51z-bQOfbaJt2zWOm")));
    System.out.println (exc.nft_item_get_content (new Address ("EQDye65-jeR8kz8MlfnS0qX-5HPF_Zq4pZSKrLFSedJumy89")));

    System.out.println("completed");
    exc.stop();
    System.exit(-1);
  }
}
