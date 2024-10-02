package org.ton.java.tonlib.types;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.ton.java.tonlib.base.TypedAsyncObject;

import java.util.List;

@SuperBuilder
@Data
@AllArgsConstructor
@NoArgsConstructor

//raw.transaction address:accountAddress utime:int53 data:bytes transaction_id:internal.transactionId fee:int64 storage_fee:int64 other_fee:int64 in_msg:raw.message out_msgs:vector<raw.message> = raw.Transaction;
public class RawTransaction extends TypedAsyncObject {
    private AccountAddress address;
    private long utime;
    private String data;
    private LastTransactionId transaction_id;
    private String fee;
    private String storage_fee;
    private String other_fee;
    private RawMessage in_msg;
    private List<RawMessage> out_msgs;

    @Override
    public String getTypeObjectName() {
        return "raw.transaction";
    }
}
