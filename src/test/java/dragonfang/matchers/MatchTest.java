package dragonfang.matchers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.entities.Entity;
import dragonfang.entities.FunctionEntity;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class MatchTest extends AbstractDragonFangTest
{

    protected ProgramBuilder secBuilder;
    protected Program secProgram;

    @Before
    public void setUp() throws Exception
    {
        super.setUp();

        secBuilder = getProgramBuilderCopy();
        secProgram = secBuilder.getProgram();
    }

    @After
    public void tearDown() throws Exception
    {
        secBuilder.dispose();
    }

    @Test
    public void testMatch()
    {
        Function simpleFunction = getSimpleFunction(builder);
        Function simpleFunction2 = getSimpleFunction(secBuilder);
        assertNotSame(simpleFunction, simpleFunction2);

        double similarity = 0.1;
        double confidence = 0.2;

        String reason = "This is the reason";

        Entity srcEntity = new FunctionEntity(simpleFunction);
        Entity dstEntity = new FunctionEntity(simpleFunction2);
        Match match = new Match(srcEntity, dstEntity, similarity, confidence, reason);

        assertSame("Source function should be correct.", srcEntity,
                   match.getSourceEntity());
        assertSame("Destination function should be correct.", dstEntity,
                   match.getDestinationEntity());

        assertEquals("Similarity should be correct.", similarity,
                     match.getSimilarityScore(), 0.0);
        assertEquals("Confidence should be correct.", confidence,
                     match.getConfidenceScore(), 0.0);

        assertEquals("Reason should be correct", reason, match.getReason());
    }
}
