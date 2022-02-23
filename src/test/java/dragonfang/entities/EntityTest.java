package dragonfang.entities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.entities.Entity.GranularityType;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class EntityTest extends AbstractDragonFangTest
{

    @Test
    public void testFunctionEntity() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction = getSimpleFunction(builder);
        FunctionEntity entity = new FunctionEntity(simpleFunction);

        assertTrue("Same entity should be equal", entity.equals(entity));
        assertEquals("Function should be correct", simpleFunction, entity.getFunction());
        assertEquals("Address view should be function body", simpleFunction.getBody(),
                     entity.getAddresses());
        assertEquals("Program should be correct", program, entity.getProgram());
        assertEquals("Granularity should be function granularity",
                     GranularityType.FUNCTION, entity.getGranularity());
    }

    @Test
    public void testBasicBlockEntity() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction = getSimpleFunction(builder);
        BasicBlockModel basicBlockModel = new BasicBlockModel(program);
        CodeBlockIterator codeBlockIterator =
            basicBlockModel.getCodeBlocksContaining(simpleFunction.getBody(), monitor);
        CodeBlock codeBlock = codeBlockIterator.next();

        BasicBlockEntity entity = new BasicBlockEntity(codeBlock, program);

        assertTrue("Same entity should be equal", entity.equals(entity));
        assertEquals("Code Block should be correct", codeBlock, entity.getCodeBlock());
        assertEquals("Address view should be the code block", codeBlock,
                     entity.getAddresses());
        assertEquals("Program should be correct", program, entity.getProgram());
        assertEquals("Granularity should be function granularity",
                     GranularityType.BASIC_BLOCK, entity.getGranularity());
    }
}
