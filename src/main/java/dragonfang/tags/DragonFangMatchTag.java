package dragonfang.tags;

import ghidra.feature.vt.api.main.VTMatchTag;

public abstract class DragonFangMatchTag implements VTMatchTag {

	public enum DragonFangMatchTagType {
		BEST_TAG_TYPE, PARTIAL_TAG_TYPE, UNRELIABLE_TAG_TYPE,
	}

	private DragonFangMatchTagType type;
	private String reason;

	public DragonFangMatchTag(String reason, DragonFangMatchTagType type) {
		this.reason = reason;
		this.type = type;
	}

	public String getReason() {
		return reason;
	}
	
	public DragonFangMatchTagType getDragonFangMatchTagType()
	{
		return type;
	}

	@Override
	public int compareTo(VTMatchTag o) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String getName() {
		return reason;
	}

	@Override
	public String toString() {
		return "Best Match";
	}
}
