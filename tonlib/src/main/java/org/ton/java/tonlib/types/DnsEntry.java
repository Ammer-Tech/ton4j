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
public class DnsEntry extends TypedAsyncObject {
    private String name;
    private String category;
    private DnsEntryData entry;

    @Override
    public String getTypeObjectName() {
        return "dns.entry";
    }
}
