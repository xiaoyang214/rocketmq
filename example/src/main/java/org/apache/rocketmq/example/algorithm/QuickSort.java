package org.apache.rocketmq.example.algorithm;

/**
 * @author wenbiao.yang
 */
public class QuickSort {

    public static void sort(int[] arr) {
        int start = 0, end = arr.length - 1;
        quickSort(arr, start, end);
    }

    private static void quickSort(int[] arr, int start, int end) {
        if (start >= end) {
            return;
        }
        int partition = partition(arr, start, end);
        quickSort(arr, start, partition - 1);
        quickSort(arr, partition + 1, end);
    }

    // 找到一个基准值，将小于基准值的都放到左边，每次从没有处理过的分区内获取一个元素进行比较
    public static int partition(int[] arr, int start, int end) {
        int base = arr[end];
        int i = start;
        for (int j = start; j < end; j++) {
            if (arr[j] < base) {
                swap(arr, i, j);
                i++;
            }
        }
        swap(arr, i, end);
        return i;
    }

    private static void swap(int[] arr, int start, int end) {
        int tmp = arr[end];
        arr[end] = arr[start];
        arr[start] = tmp;
    }

    public static void main(String[] args) throws Exception {
        // int[] a = {1,5,8,6,7,12,18,15,13,9,3};
        // // 1,3,5,8,6,7,12,18,15,13,9,8
        // sort(a);
        // for (int value : a) {
        //     System.out.println(value);
        // }
        System.out.println(1 << 2);
    }
}
