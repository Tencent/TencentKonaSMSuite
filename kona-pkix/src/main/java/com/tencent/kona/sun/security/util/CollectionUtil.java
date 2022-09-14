package com.tencent.kona.sun.security.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CollectionUtil {

    public static <E> List<E> list(E... elements) {
        return Arrays.asList(elements);
    }

    public static <E> Set<E> set(E... elements) {
        if (elements == null || elements.length == 0) {
            return Collections.emptySet();
        }

        Set<E> set = new HashSet<E>(list(elements));
        return Collections.unmodifiableSet(set);
    }

    public static <K, V> Map<K, V> map(K key, V value) {
        Map<K, V> map = new HashMap<K, V>();
        map.put(key, value);
        return Collections.unmodifiableMap(map);
    }

    public static <K, V> Map<K, V> map(
            K key1, V value1,
            K key2, V value2) {
        Map<K, V> map = new HashMap<K, V>();
        map.put(key1, value1);
        map.put(key2, value2);
        return Collections.unmodifiableMap(map);
    }

    public static <K, V> Map<K, V> map(
            K key1, V value1,
            K key2, V value2,
            K key3, V value3) {
        Map<K, V> map = new HashMap<K, V>();
        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        return Collections.unmodifiableMap(map);
    }

    public static <K, V> Map<K, V> map(
            K key1, V value1,
            K key2, V value2,
            K key3, V value3,
            K key4, V value4) {
        Map<K, V> map = new HashMap<K, V>();
        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        return Collections.unmodifiableMap(map);
    }

    public static <K, V> Map<K, V> map(
            K key1, V value1,
            K key2, V value2,
            K key3, V value3,
            K key4, V value4,
            K key5, V value5) {
        Map<K, V> map = new HashMap<K, V>();
        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        return Collections.unmodifiableMap(map);
    }

    public static <K, V> Map<K, V> map(
            K key1, V value1,
            K key2, V value2,
            K key3, V value3,
            K key4, V value4,
            K key5, V value5,
            K key6, V value6) {
        Map<K, V> map = new HashMap<K, V>();
        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        return Collections.unmodifiableMap(map);
    }
}
