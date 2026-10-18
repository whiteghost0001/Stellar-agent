'use client';

import { useCallback, useState } from 'react';
import type { Signer } from 'marc-stellar-sdk';
import { useCommerce } from './useCommerce';
import type { CreateJobParams, CreateJobResult } from './useCommerce';

export interface UseCreateJobResult {
  /** Create a job on-chain with automatic status and in-flight tracking. */
  createJob: (
    paramsOrProvider: CreateJobParams | string | Signer,
    evaluator?: string,
    budget?: bigint | string | number,
    description?: string,
    token?: string,
  ) => Promise<CreateJobResult>;
  /** The created job result (id and txHash), or null. */
  result: CreateJobResult | null;
  /** True while the transaction is being submitted and confirmed on-chain. */
  isPending: boolean;
  /** Error encountered during job creation, if any. */
  error: Error | null;
  /** Reset creation state. */
  reset: () => void;
}

/**
 * useCreateJob provides a focused hook for escrow job creation.
 */
export function useCreateJob(): UseCreateJobResult {
  const commerce = useCommerce();
  const [result, setResult] = useState<CreateJobResult | null>(null);

  const createJob = useCallback(
    async (
      paramsOrProvider: CreateJobParams | string | Signer,
      evaluator?: string,
      budget?: bigint | string | number,
      description?: string,
      token?: string,
    ): Promise<CreateJobResult> => {
      const res = await commerce.createJob(
        paramsOrProvider,
        evaluator,
        budget,
        description,
        token,
      );
      setResult(res);
      return res;
    },
    [commerce],
  );

  const reset = useCallback(() => {
    setResult(null);
    commerce.reset();
  }, [commerce]);

  return {
    createJob,
    result,
    isPending: commerce.isPending,
    error: commerce.error,
    reset,
  };
}

export default useCreateJob;
