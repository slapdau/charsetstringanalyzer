/*
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
package nz.gen.coffee.ghidra.string;

import java.util.Arrays;
import java.util.List;

import javax.swing.event.EventListenerList;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

public class SearchCharsetsTableModel implements TableModel {
    
    private static final Class<?>[] COLUMN_TYPES = {
        String.class,
        Boolean.class,
    };
    
    private static final String[] COLUMN_NAMES = {
      "Character Set",
      "Search",
    };
    
    private final EventListenerList listeners = new EventListenerList();
    private final String[] allCharsets;
    private final List<String> charsets;

    
    
    public SearchCharsetsTableModel(String[] allCharsets, List<String> charsets) {
        this.allCharsets = Arrays.copyOf(allCharsets, allCharsets.length);
        Arrays.sort(this.allCharsets);
        this.charsets = charsets;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return COLUMN_TYPES[columnIndex];
    }

    @Override
    public int getRowCount() {
        return allCharsets.length;
    }

    @Override
    public int getColumnCount() {
        return COLUMN_TYPES.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch (columnIndex) {
        case 0:
            return allCharsets[rowIndex];
        case 1:
            return charsets.contains(allCharsets[rowIndex]);
        default:
            return null;    
        }
    }
    
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 1;
    }
    
    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 1) {
            boolean hasCharset = (Boolean) aValue;
            if (hasCharset) {
                charsets.add(allCharsets[rowIndex]);
            } else {
                charsets.remove(allCharsets[rowIndex]);
            }
            fireTableChanged(new TableModelEvent(this, rowIndex, rowIndex, columnIndex));
        }
    }

    @Override
    public void addTableModelListener(TableModelListener l) {
        listeners.add(TableModelListener.class, l);
    }

    @Override
    public void removeTableModelListener(TableModelListener l) {
        listeners.remove(TableModelListener.class, l);
    }

    private void fireTableChanged(TableModelEvent event) {
        for (var listener : listeners.getListeners(TableModelListener.class)) {
            listener.tableChanged(event);
        }
    }

}
