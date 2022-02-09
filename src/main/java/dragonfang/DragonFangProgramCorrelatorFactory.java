/* ###
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dragonfang;

import java.util.ArrayList;
import java.util.List;

import dragonfang.counter.maps.InstrCountMap;
import dragonfang.counter.maps.LazyInstrCountMap;
import dragonfang.counters.InstrCounter;
import dragonfang.counters.PCodeInstrCounter;
import dragonfang.features.BBCountFeature;
import dragonfang.features.CyclomaticComplexityFeature;
import dragonfang.features.EdgeCountFeature;
import dragonfang.features.Feature;
import dragonfang.features.FuncCallCountFeature;
import dragonfang.features.IndJmpCountFeature;
import dragonfang.features.extractors.FeatureExtractor;
import dragonfang.features.extractors.FeatureListVectorExtractor;
import dragonfang.features.maps.FeatureMap;
import dragonfang.features.maps.LazyFeatureMap;
import dragonfang.features.metrics.CosineSimilarityMetric;
import dragonfang.features.metrics.FeatureSimilarityMetric;
import dragonfang.graphs.builders.CallGraphBuilder;
import dragonfang.graphs.builders.GraphBuilder;
import dragonfang.graphs.maps.ControlFlowGraphMap;
import dragonfang.graphs.maps.LazyControlFlowGraphMap;
import dragonfang.graphs.wrapper.ExtendedDirectGraphWrapper;
import dragonfang.matchers.Matcher;
import dragonfang.matchers.PrimeProductMatcher;
import dragonfang.matchers.SimilarityFeatureMatcher;
import dragonfang.matchers.UniqueFeatureMatcher;
import dragonfang.primes.InstrPrimeProductCalculator;
import dragonfang.primes.PCodePrimeProductCalculator;
import dragonfang.primes.maps.PrimeProductMap;
import dragonfang.propagators.Propagator;
import dragonfang.propagators.PropertyBasedPropagator;
import dragonfang.propagators.properties.AfterAddressPropagationProperty;
import dragonfang.propagators.properties.BeforeAddressPropagationProperty;
import dragonfang.propagators.properties.ChildCallGraphPropagationProperty;
import dragonfang.propagators.properties.ParentCallGraphPropagationProperty;
import dragonfang.tags.MatchTagAssigner;
import dragonfang.tags.ThresholdMatchTagAssigner;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CyclomaticComplexity;

public class DragonFangProgramCorrelatorFactory extends VTAbstractProgramCorrelatorFactory {

	static final String NAME = "Dragon Fang";
	static final String DESC = "A function similarity analyser for the Ghidra dragon.";

	public static final String PROPAGATION_STEP_OPT = "Do Propagation Step";
	public static final boolean PROPAGATION_STEP_DEFAULT = true;

	@Override
	public int getPriority() {
		return 80;
	}

	private List<Propagator> createProgatorList(ExtendedDirectGraphWrapper srcCallGraphWrapper,
			ExtendedDirectGraphWrapper dstCallGraphWrapper) {

		List<Propagator> propagators = new ArrayList<Propagator>();

		ChildCallGraphPropagationProperty srcChildProperty = new ChildCallGraphPropagationProperty(srcCallGraphWrapper);
		ChildCallGraphPropagationProperty dstChildProperty = new ChildCallGraphPropagationProperty(dstCallGraphWrapper);
		PropertyBasedPropagator childPropagator = new PropertyBasedPropagator(srcChildProperty, dstChildProperty);
		propagators.add(childPropagator);

		ParentCallGraphPropagationProperty srcParentProperty = new ParentCallGraphPropagationProperty(
				srcCallGraphWrapper);
		ParentCallGraphPropagationProperty dstParentProperty = new ParentCallGraphPropagationProperty(
				dstCallGraphWrapper);
		PropertyBasedPropagator parentPropagator = new PropertyBasedPropagator(srcParentProperty, dstParentProperty);
		propagators.add(parentPropagator);

		AfterAddressPropagationProperty afterPropagationProperty = new AfterAddressPropagationProperty();
		PropertyBasedPropagator afterPropagator = new PropertyBasedPropagator(afterPropagationProperty,
				afterPropagationProperty);
		propagators.add(afterPropagator);

		BeforeAddressPropagationProperty beforePropagationProperty = new BeforeAddressPropagationProperty();
		PropertyBasedPropagator beforePropagator = new PropertyBasedPropagator(beforePropagationProperty,
				beforePropagationProperty);
		propagators.add(beforePropagator);

		return propagators;
	}

	private List<Feature> createFeatureList(ControlFlowGraphMap cfgMap, InstrCountMap instrCountMap,
			CyclomaticComplexity cyclimaticComplexity) {

		List<Feature> features = new ArrayList<Feature>();

		BBCountFeature bbCountFeature = new BBCountFeature(cfgMap);
		features.add(bbCountFeature);

		EdgeCountFeature edgeCountFeature = new EdgeCountFeature(cfgMap);
		features.add(edgeCountFeature);

		CyclomaticComplexityFeature cyclomaticComplexityFeature = new CyclomaticComplexityFeature(cyclimaticComplexity);
		features.add(cyclomaticComplexityFeature);

		FuncCallCountFeature funcCallCountFeature = new FuncCallCountFeature(instrCountMap);
		features.add(funcCallCountFeature);

		IndJmpCountFeature indJmpCountFeature = new IndJmpCountFeature(instrCountMap);
		features.add(indJmpCountFeature);

		return features;
	}

	private List<Matcher> createMatchersList(FeatureMap srcFeatureMap, FeatureMap dstFeatureMap,
			PrimeProductMap srcPrimeProductMap, PrimeProductMap dstPrimeProductMap, FeatureSimilarityMetric similarityMetric) {

		List<Matcher> matchers = new ArrayList<Matcher>();

		UniqueFeatureMatcher uniqueFeatureMatcher = new UniqueFeatureMatcher(srcFeatureMap, dstFeatureMap);
		matchers.add(uniqueFeatureMatcher);

		PrimeProductMatcher primeProductMatcher = new PrimeProductMatcher(srcPrimeProductMap, dstPrimeProductMap);
		matchers.add(primeProductMatcher);

		SimilarityFeatureMatcher similarityFeatureMatcher = new SimilarityFeatureMatcher(srcFeatureMap, dstFeatureMap,
				similarityMetric);
		matchers.add(similarityFeatureMatcher);

		return matchers;
	}

	@Override
	protected VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram, AddressSetView destinationAddressSet,
			VTOptions options) {

		ControlFlowGraphMap srcCFGMap = new LazyControlFlowGraphMap();
		ControlFlowGraphMap dstCFGMap = new LazyControlFlowGraphMap();

		InstrCounter srcInstrCounter = new PCodeInstrCounter();
		InstrCountMap srcInstrCountMap = new LazyInstrCountMap(srcInstrCounter);
		InstrCounter dstInstrCounter = new PCodeInstrCounter();
		InstrCountMap dstInstrCountMap = new LazyInstrCountMap(dstInstrCounter);

		CyclomaticComplexity cyclimaticComplexity = new CyclomaticComplexity();

		FeatureExtractor srcFeatureExtractor = new FeatureListVectorExtractor(
				createFeatureList(srcCFGMap, srcInstrCountMap, cyclimaticComplexity));
		FeatureMap srcFeatureMap = new LazyFeatureMap(srcFeatureExtractor);
		FeatureExtractor dstFeatureExtractor = new FeatureListVectorExtractor(
				createFeatureList(dstCFGMap, dstInstrCountMap, cyclimaticComplexity));
		FeatureMap dstFeatureMap = new LazyFeatureMap(dstFeatureExtractor);

		InstrPrimeProductCalculator primeProduct = new PCodePrimeProductCalculator();

		PrimeProductMap srcPrimeProductMap = new PrimeProductMap(primeProduct, srcInstrCountMap);
		PrimeProductMap dstPrimeProductMap = new PrimeProductMap(primeProduct, dstInstrCountMap);

		FeatureSimilarityMetric similarityMetric = new CosineSimilarityMetric();

		List<Matcher> matcherList = createMatchersList(srcFeatureMap, dstFeatureMap, srcPrimeProductMap,
				dstPrimeProductMap, similarityMetric);

		MatchTagAssigner matchTagAssigner = new ThresholdMatchTagAssigner();

		GraphBuilder srcCallbuilder = new CallGraphBuilder(sourceProgram);
		ExtendedDirectGraphWrapper srcCallGraphWrapper = new ExtendedDirectGraphWrapper(srcCallbuilder);
		GraphBuilder dstCallbuilder = new CallGraphBuilder(destinationProgram);
		ExtendedDirectGraphWrapper dstCallGraphWrapper = new ExtendedDirectGraphWrapper(dstCallbuilder);

		List<Propagator> propagatorList = createProgatorList(srcCallGraphWrapper, dstCallGraphWrapper);

		DragonFangData dragonFangData = new DragonFangData(matcherList, propagatorList, matchTagAssigner,
				srcCallGraphWrapper, dstCallGraphWrapper);

		return new DragonFangProgramCorrelator(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
				destinationAddressSet, options, NAME, dragonFangData);
	}

	@Override
	public String getName() {

		return NAME;
	}

	@Override
	public VTOptions createDefaultOptions() {

		VTOptions options = new VTOptions(NAME);
		options.setBoolean(PROPAGATION_STEP_OPT, PROPAGATION_STEP_DEFAULT);
		return options;
	}

	@Override
	public String getDescription() {

		return DESC;
	}
}