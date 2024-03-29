package com.ljh.apiclient.configeditor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class PropertiesEditorConfig {

	public static final class PropertiesEditorConfigBuilder {

		private final List<PropertyType<?>> types = new ArrayList<>();

		private PropertyType<?> defaultType;

		private PropertiesEditorConfigBuilder() {
		}

		/**
		 * Create the configuration.
		 * 
		 * @return The configuration.
		 */
		public PropertiesEditorConfig build() {
			return new PropertiesEditorConfig(this);
		}

		/**
		 * Adds a type to be used in the PropertiesEditor. The entries are shown
		 * in the UI in the order in which they were added through this method.
		 * 
		 * @param type
		 *            The type to add.
		 * @return The builder instance for method chaining.
		 */
		public PropertiesEditorConfigBuilder addType(PropertyType<?> type) {
			Objects.requireNonNull(type, "type was null");
			types.add(type);
			if (defaultType == null) {
				defaultType = type;
			}
			return this;
		}

		/**
		 * Adds a type to be used as a default (i.e. when clicking the "Add"
		 * button).
		 * 
		 * @param defaultType
		 *            The type to add.
		 * @return The builder instnace for method chaining.
		 */
		public PropertiesEditorConfigBuilder addDefaultType(PropertyType<?> defaultType) {
			Objects.requireNonNull(defaultType, "defaultType was null");
			if (!types.contains(defaultType)) {
				types.add(defaultType);
			}
			this.defaultType = defaultType;
			return this;
		}

	}

	public static PropertiesEditorConfigBuilder builder() {
		return new PropertiesEditorConfigBuilder();
	}

	public static PropertiesEditorConfig defaultConfig() {
		PropertiesEditorConfigBuilder builder = builder();

		builder.addType(new PropertyTypes.ListType("List"));
		builder.addType(new PropertyTypes.MapType("Map"));

		builder.addDefaultType(new PropertyTypes.StringType("String", ""));
		builder.addType(new PropertyTypes.BooleanType("Boolean", true));
		builder.addType(new PropertyTypes.LongType("Long", 0l));
		builder.addType(new PropertyTypes.IntegerType("Integer", 0));
		builder.addType(new PropertyTypes.DoubleType("Double", 0.));
		builder.addType(new PropertyTypes.FloatType("Float", 0f));

		return builder.build();
	}

	private final List<PropertyType<?>> types;

	private final PropertyType<?> defaultType;

	private PropertiesEditorConfig(PropertiesEditorConfigBuilder builder) {
		types = new ArrayList<>(builder.types);
		defaultType = builder.defaultType;
	}

	public PropertyType<?>[] getTypes() {
		return types.toArray(new PropertyType[0]);
	}
	
	public PropertyType<?> getType(Class<?> javaType) {
		Objects.requireNonNull(javaType, "javaType was null");
		for (PropertyType<?> type : getTypes()) {
			if (type.getType().isAssignableFrom(javaType)) {
				return type;
			}
		}
		throw new IllegalArgumentException("Unsupported type: " + javaType.getName());
	}

	public PropertyNode fromObject(String key, Object object) {
		Objects.requireNonNull(object, "object was null");
		PropertyType<?> propertyType = getType(object.getClass());
		return propertyType.fromObject(key, object, this);
	}

	public PropertyNode fromObject(Object object) {
		return fromObject(null, object);
	}

	public PropertyType<?> getDefaultType() {
		return defaultType;
	}

}
