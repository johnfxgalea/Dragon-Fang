package dragonfang.features;

import dragonfang.entities.Entity;

public abstract class AbstractFeature implements Feature
{

    public abstract boolean isEntityValid(Entity entity);
}
