package org.ton.java.tonlib.queries;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.ton.java.tonlib.base.TypedAsyncObject;
import org.ton.java.tonlib.types.AccountAddressOnly;

@SuperBuilder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateAndSendRawMessageQuery extends TypedAsyncObject {
    private AccountAddressOnly destination;
    private String initial_account_state;
    private String data;

    @Override
    public String getTypeObjectName() {
        return "raw.createAndSendMessage";
    }
}
