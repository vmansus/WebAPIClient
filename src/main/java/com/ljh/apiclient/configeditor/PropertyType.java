package com.ljh.apiclient.configeditor;

public interface PropertyType<TYPE> {

	/**
	 * @return <code>true</code> in case this is a collection type (i.e.
	 *         contains children).
	 */
	boolean isCollection();

	/**
	 * @return The default value of the property. <code>null</code> for
	 *         collection types.
	 */
	TYPE getDefaultValue();

	/**
	 * @return The underlying Java type.
	 */
	Class<? super TYPE> getType();

	/**
	 * Converts a Java object to a property node.
	 * 
	 * @param key
	 *            (optional) key.
	 * @param object
	 *            The object.
	 * @param config
	 *            The configuration.
	 * @return The property node.
	 */
	PropertyNode fromObject(String key, Object object, PropertiesEditorConfig config);

	/**
	 * Converts a PropertyNode to a Java object.
	 * 
	 * @param propertyNode
	 *            The property node.
	 * @return The Java object.
	 */
	TYPE toObject(PropertyNode propertyNode);
}
