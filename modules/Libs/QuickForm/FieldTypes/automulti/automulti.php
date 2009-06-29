<?php
/**
 * HTML class for a autocomplete-multiselect combo
 *
 * @author Arkadiusz Bisaga <abisaga@telaxus.com>
 * @license MIT
 * @version 1.0
 * @package epesi-libs
 * @subpackage QuickForm
 */
require_once('HTML/QuickForm/select.php');
require_once('modules/Libs/QuickForm/FieldTypes/autocomplete/autocomplete.php');

class HTML_QuickForm_automulti extends HTML_QuickForm_element {

    /**
     * Contains the callback for select options
     *
     * @var       callback
     * @access    private
     */
    var $_options_callback = null;

	/**
	 * Contains the callback for option formatting
	 * 
	 * @var			callback
	 * @access		private
	 */
    var $_format_callback = null;

    /**
     * Contains the arguments for callback for select options
     *
     * @var       callback
     * @access    private
     */
    var $_options_callback_args = null;

    /**
     * Default values of the SELECT
     *
     * @var       string
     * @access    private
     */
    var $_values = array();

    /**
     * Hash table to hold original keys of given options
     *
     * @var       string
     * @access    private
     */
    var $keyhash = array();

	private $list_sep = '__SEP__';
    /**
     * Class constructor
     *
     * @param     string    Select name attribute
     * @param     mixed     Label(s) for the select
     * @param     mixed     Data to be used to populate options
     * @param     mixed     Either a typical HTML attribute string or an associative array
     * @access    public
     * @return    void
     */
    function HTML_QuickForm_automulti($elementName=null, $elementLabel=null, $options_callback=null, $options_callback_args=null, $format_callback=null, $attributes=null)
    {
        HTML_QuickForm_element::HTML_QuickForm_element($elementName, $elementLabel, $attributes);
        $this->_persistantFreeze = true;
        $this->_type = 'select';
        if ($options_callback) $this->_options_callback = $options_callback;
        if ($options_callback_args) $this->_options_callback_args = $options_callback_args;
        if ($format_callback) $this->_format_callback = $format_callback;
    }
    
    public static function get_autocomplete_suggestbox($string, $callback=null, $args=null, $format=null) {
    	if (!is_array($args)) $args = array();
    	array_unshift($args, $string);
    	$result = call_user_func_array($callback, $args);
    	$ret = '<ul>';
    	foreach ($result as $k=>$v) {
    		$disp = call_user_func($format, $k);
			$ret .= '<li><span style="display:none;">'.$k.'__'.$disp.'</span><span class="informal">'.$v.'</span></li>';
    	}
    	$ret .= '</ul>';
    	return $ret;
    }

    /**
     * Returns the current API version
     *
     * @access    public
     * @return    double
     */
    function apiVersion()
    {
        return 2.3;
    }

    /**
     * Sets the default values of the select box
     *
     * @param     mixed    $values  Array or comma delimited string of selected values
     * @access    public
     * @return    void
     */
    function setSelected($values)
    {
    	if (!is_array($this->_values)) $this->_values = array();
        if (!is_array($values)) {
            $values = array($values);
        }
    	foreach($values as $k=>$v)
        	if (!in_array($v,$this->_values)) $this->_values[] = $v;
    }

    /**
     * Returns an array of the selected values
     *
     * @access    public
     * @return    array of selected values
     */
    function getSelected()
    {
        return $this->_values;
    }

    function getMultiple()
    {
        return true;
    }
    /**
     * Sets the input field name
     *
     * @param     string    $name   Input field name attribute
     * @access    public
     * @return    void
     */
    function setName($name)
    {
        $this->updateAttributes(array('name' => $name));
    }

    /**
     * Returns the element name
     *
     * @access    public
     * @return    string
     */
    function getName()
    {
        return $this->getAttribute('name');
    }

    /**
     * Returns the element name (possibly with brackets appended)
     *
     * @access    public
     * @return    string
     */
    function getPrivateName()
    {
        return $this->getName();
    }

    /**
     * Sets the value of the form element
     *
     * @param     mixed    $values  Array or comma delimited string of selected values
     * @access    public
     * @return    void
     */
    function setValue($value)
    {
        $this->setSelected($value);
    }

    /**
     * Returns an array of the selected values
     *
     * @access    public
     * @return    array of selected values
     */
    function getValue()
    {
        return $this->_values;
    }

    /**
     * Sets the select field size
     *
     * @param     int    $size  Size of select  field
     * @access    public
     * @return    void
     */
    function setSize($size)
    {
        $this->updateAttributes(array('size' => $size));
    }

    /**
     * Returns the select field size
     *
     * @access    public
     * @return    int
     */
    function getSize()
    {
        return $this->getAttribute('size');
    }

    /**
     * Returns the SELECT in HTML
     *
     * @access    public
     * @return    string
     */
    function toHtml()
    {
    	//print_r($this->_values);
		$this->updateAttributes(array('multiple' => 'multiple'));
        if ($this->_flagFrozen) {
            return $this->getFrozenHtml();
        } else {
			$tabs    = $this->_getTabs();
			$strHtml = '';
			
			if ($this->getComment() != '') {
			    $strHtml .= $tabs . '<!-- ' . $this->getComment() . " //-->\n";
			}
			
			$myName = $this->getName();

			load_js('modules/Libs/QuickForm/FieldTypes/automulti/automulti.js');

//			$this->setName($myName . '__search');
//			$this->_attributes['id'] = $myName . '__search';
//			$attrString = $this->_getAttrString($this->_attributes);
//			$attrArray = $this->getAttributes();
			$searchElement = '';
			$search = new HTML_QuickForm_autocomplete($myName.'__search','', array('HTML_QuickForm_automulti','get_autocomplete_suggestbox'), array($this->_options_callback, $this->_options_callback_args, $this->_format_callback));
			$search->on_hide_js('automulti_on_hide("'.$myName.'","'.$this->list_sep.'")');
			
			$searchElement .= $tabs . $search->toHtml()."\n";
//			if (isset($this->_values[0]) && eregi($this->list_sep,$this->_values[0])) {
//		        $this->_values = explode($this->list_sep,$this->_values[0]);
//		        array_shift($this->_values);
//			}
//			$i = 0;
//            foreach ($this->_options as $k=>$option) {
//            	$this->keyhash[$i] = $this->_options[$k]['attr']['value'];
//            	$kv = array_search($this->_options[$k]['attr']['value'], $this->_values);
//            	$i++;
//				if ($leave_selected || !(is_array($this->_values) && in_array((string)$this->_options[$k]['attr']['value'], $this->_values)))
//                	$fromElement .= $tabs . "\t<option " . $this->_getAttrString($this->_options[$k]['attr']) . ">" . $this->_options[$k]['text'] . "</option>\n";
//            }
//			$fromElement .= $tabs . '</select>';

			$this->setName($myName.'__display');

			$mainElement = '';
			$list = '';
			$attrString = $this->_getAttrString($this->_attributes);
			$mainElement .= $tabs . '<select' . $attrString . ' onclick="automulti_remove_button_update(\''.$myName.'\');">'."\n";
			print_r($this->_values);
			if (!isset($this->_values)) {
				$this->_values = array();
			} elseif (!is_array($this->_values)) {
				$this->_values = explode($this->list_sep, $this->_values);
				array_shift($this->_values);
			}
			foreach ($this->_values as $value) {
				$mainElement .= $tabs . "\t".'<option value>' . call_user_func($this->_format_callback, $value) . '</option>'."\n";
				$list .= '__SEP__'.$value;
            }
			$mainElement .= $tabs . '</select>';

			$strHtml .= $tabs . '<table id="automulti">';
            $strHtml .= $tabs . '<tr>'.
            			$tabs . '<td class="search-element">' . $searchElement . '</td>'.
						$tabs . '<td class="button disabled" id="automulti_button_style_'.$myName.'">'.'<input type="button" onclick="automulti_remove_button_action(\''.$myName.'\', \''.$this->list_sep.'\');" value="'.Base_LangCommon::ts('Libs_QuickForm','Remove').'">'.'</td>' .
								'</tr>';

			$strHtml .= $tabs . '<tr><td class="main-element" colspan="2">' . $mainElement . '</td></tr></table>';

			$this->setName($myName);

			$strHtml .= $tabs . '<input type="hidden" name="'.$myName.'" value="'.$list.'" />'."\n";
			return $strHtml;
        }
    }

    /**
     * Returns the value of field without HTML tags
     *
     * @access    public
     * @return    string
     */
    function getFrozenHtml()
    {
    	$html = '';
    	foreach($this->_options as $k=>$v)
	        if (in_array($v['attr']['value'],$this->_values)) $html .= empty($v['text'])? '&nbsp;':'<span>'.$v['text'].'</span><br />';
        return $html;
    }

   /**
    * We check the options and return only the values that _could_ have been
    * selected. We also return a scalar value if select is not "multiple"
    */
    function exportValue(&$submitValues, $assoc = false)
    {
        $value = $this->_findValue($submitValues);
        if (is_null($value)) {
            $value = $this->getValue();
        }
        $cleanValue = explode('__SEP__',$value);
        array_shift($cleanValue);
		return $this->_prepareValue($cleanValue, $assoc);
    }

    function onQuickFormEvent($event, $arg, &$caller)
    {
        if ('updateValue' == $event) {
            $value = $this->_findValue($caller->_constantValues);
            if (null === $value) {
                $value = $this->_findValue($caller->_submitValues);
                // Fix for bug #4465 & #5269
                // XXX: should we push this to element::onQuickFormEvent()?
                if (null === $value && (!$caller->isSubmitted())) {
                    $value = $this->_findValue($caller->_defaultValues);
                }
            }
            if (null !== $value) {
                $this->setValue($value);
            }
            return true;
        } else {
            return parent::onQuickFormEvent($event, $arg, $caller);
        }
    }

}
?>