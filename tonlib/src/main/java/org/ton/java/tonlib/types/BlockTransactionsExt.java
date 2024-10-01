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
public class BlockTransactionsExt extends TypedAsyncObject {
    private BlockIdExt id;
    private long req_count;
    private boolean incomplete;
    private List<RawTransaction> transactions;

    @Override
    public String getTypeObjectName() {
        return "blocks.transactionsExt";
    }
}
