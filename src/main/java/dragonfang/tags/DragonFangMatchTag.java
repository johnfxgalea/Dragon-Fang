package dragonfang.tags;

import ghidra.feature.vt.api.main.VTMatchTag;

public abstract class DragonFangMatchTag implements VTMatchTag
{

    public enum DragonFangMatchTagType {
        BEST_TAG_TYPE,
        PARTIAL_TAG_TYPE,
        UNRELIABLE_TAG_TYPE,
    }

    private DragonFangMatchTagType type;
    private String reason;

    public DragonFangMatchTag(String reason, DragonFangMatchTagType type)
    {
        this.reason = reason;
        this.type = type;
    }

    public String getReason()
    {
        return reason;
    }

    public DragonFangMatchTagType getDragonFangMatchTagType()
    {
        return type;
    }
}
