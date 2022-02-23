package dragonfang.entities;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Program;

public class BasicBlockEntity extends Entity
{

    private CodeBlock codeBlock;
    private Program program;

    public BasicBlockEntity(CodeBlock codeBlock, Program program)
    {
        super(GranularityType.BASIC_BLOCK);
        this.codeBlock = codeBlock;
        this.program = program;
    }

    @Override
    public Program getProgram()
    {
        return program;
    }

    @Override
    public AddressSetView getAddresses()
    {
        return codeBlock;
    }

    public CodeBlock getCodeBlock()
    {
        return codeBlock;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (!(obj instanceof BasicBlockEntity))
            return false;

        BasicBlockEntity cmpBBEntity = (BasicBlockEntity) obj;
        return codeBlock.equals(cmpBBEntity.codeBlock);
    }

    @Override
    public int hashCode()
    {
        return codeBlock.hashCode();
    }
}
