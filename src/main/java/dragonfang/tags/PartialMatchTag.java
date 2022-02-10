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

package dragonfang.tags;

import ghidra.feature.vt.api.main.VTMatchTag;

/**
 * Tag to associate with partial match results.
 */
public class PartialMatchTag extends DragonFangMatchTag {

    public PartialMatchTag() {
        super("No reason", DragonFangMatchTagType.PARTIAL_TAG_TYPE);
    }

    public PartialMatchTag(String reason) {
        super(reason, DragonFangMatchTagType.PARTIAL_TAG_TYPE);
    }

    @Override
    public int compareTo(VTMatchTag o) {
        return getName().compareTo(o.getName());
    }

    @Override
    public String getName() {
        return this.toString();
    }

    @Override
    public String toString() {
        return "Partial Match - " + getReason();
    }
}
