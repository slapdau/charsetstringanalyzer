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

import java.awt.Component;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.beans.PropertyChangeListener;
import java.beans.PropertyEditor;
import java.beans.PropertyEditorSupport;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ScrollPaneConstants;

import docking.widgets.table.GTable;

public class SearchCharsetsEditor implements PropertyEditor {
    
    private final PropertyEditorSupport support = new PropertyEditorSupport(this);
    private final String[] searchableCharsets;
    private List<String> charsets;
    private final JTable editorTable = new GTable();
    private final Component editor;
    {
        editor = new JScrollPane(
            editorTable,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS
        );
        editor.setPreferredSize(new Dimension(200,200));
    }
    
    public SearchCharsetsEditor(String[] searchableCharsets) {
        this.searchableCharsets = searchableCharsets;
        this.setCharsets(new LinkedList<>());
    }

    @Override
    public void setValue(Object value) {
        if (value instanceof SearchCharsets) {
            var charsetsArray = ((SearchCharsets) value).getCharsets();
            setCharsets(new LinkedList<>(Arrays.asList(charsetsArray)));
        }
    }

    private void setCharsets(LinkedList<String> charsets) {
        this.charsets = charsets;
        var model = new SearchCharsetsTableModel(searchableCharsets, charsets);
        model.addTableModelListener(e -> {
            support.firePropertyChange();
        });
        editorTable.setModel(model);
        support.firePropertyChange();
    }

    @Override
    public Object getValue() {
        return new SearchCharsets(charsets.toArray(String[]::new));
    }

    @Override
    public boolean isPaintable() {
        return false;
    }

    @Override
    public void paintValue(Graphics gfx, Rectangle box) {
    }

    @Override
    public String getJavaInitializationString() {
        return "???";
    }

    @Override
    public String getAsText() {
        return null;
    }

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        throw new IllegalArgumentException();
    }

    @Override
    public String[] getTags() {
        return null;
    }

    @Override
    public Component getCustomEditor() {
        return editor;
    }

    @Override
    public boolean supportsCustomEditor() {
        return true;
    }

    @Override
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        support.addPropertyChangeListener(listener);
    }

    @Override
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        support.removePropertyChangeListener(listener);
    }

}
