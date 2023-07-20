package com.tencent.kona.crypto.util;

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * A worker used to clean resources, say native memory.
 */
public class Sweeper {

    private static class InstanceHolder {
        private static final Sweeper INSTANCE = new Sweeper();
    }

    /**
     * Get the default Sweeper instance.
     * Generally, it just uses this sweeper only.
     */
    public static Sweeper instance() {
        return InstanceHolder.INSTANCE;
    }

    private final Collection<ResourceHolderRef> resourceHolderRefs
            = new ConcurrentLinkedQueue<>();

    private final ReferenceQueue<Object> resourceHolderRefQueue
            = new ReferenceQueue<>();

    private class ResourceHolderRef extends PhantomReference<Object> {

        private final Runnable sweep;

        private ResourceHolderRef(Object resourceHolder,
                ReferenceQueue<Object> resourceHolderRefQueue,
                Runnable sweep) {
            super(resourceHolder, resourceHolderRefQueue);
            this.sweep = sweep;
        }

        @Override
        public void clear() {
            sweep.run();
            resourceHolderRefs.remove(this);
            super.clear();
        }
    }

    private final Thread sweeperThread;
    private boolean started = false;

    public Sweeper(boolean startImmediately) {
        sweeperThread = new Thread(() -> {
            while (true) {
                try {
                    resourceHolderRefQueue.remove().clear();
                } catch (Throwable t) {
                    // just ignore it
                }
            }
        });
        sweeperThread.setDaemon(true);

        if (startImmediately) {
            start();
        }
    }

    public Sweeper() {
        this(true);
    }

    /**
     * Start to sweep with a single thread.
     */
    public synchronized void start() {
        if (!started) {
            sweeperThread.start();
            started = true;
        }
    }

    /**
     * Registers a resource holder and a sweeping action to run when the
     * resource holder becomes phantom reachable.
     */
    public void register(Object resourceHolder, Runnable sweep) {
        Objects.requireNonNull(resourceHolder);
        Objects.requireNonNull(sweep);

        resourceHolderRefs.add(new ResourceHolderRef(
                resourceHolder, resourceHolderRefQueue, sweep));
    }

    public void clean() {
        // Do nothing
    }

    public int size() {
        return resourceHolderRefs.size();
    }

    public boolean isEmpty() {
        return resourceHolderRefs.isEmpty();
    }
}
