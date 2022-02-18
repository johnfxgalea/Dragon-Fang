package dragonfang.features;

import dragonfang.entities.Entity;
import dragonfang.entities.Entity.GranularityType;

public abstract class BasicBlockFeature extends AbstractFeature {

	public boolean isEntityValid(Entity entity)
	{
		return entity.getGranularity() == GranularityType.BASIC_BLOCK;
	}
}
