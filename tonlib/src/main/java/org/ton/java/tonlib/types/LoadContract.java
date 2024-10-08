package org.ton.java.tonlib.types;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.ton.java.tonlib.base.TypedAsyncObject;
@SuperBuilder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoadContract extends TypedAsyncObject {
    private long id;

    @Override
    public String getTypeObjectName() {
        return "smc.info";
    }
}